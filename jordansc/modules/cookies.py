from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 10


@dataclass
class CookieIssue:
    name: str
    issues: List[str]


@dataclass
class CookiesAuditResult:
    url: str
    final_url: str
    https: bool
    status_code: Optional[int]
    cookies_seen: int
    issues: List[CookieIssue]
    warnings: List[str]
    error: Optional[str] = None
    score: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Empty target")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def _calc_score(https: bool, issues_count: int, cookies_seen: int) -> int:
    # قاعدة بسيطة وواضحة:
    # 100 - (issues_count * 10) - (عدم HTTPS 20) + (0 كوكيز = ما في خصم)
    score = 100
    if not https:
        score -= 20
    if cookies_seen > 0:
        score -= issues_count * 10
    return max(0, min(100, score))


def audit_cookies(
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    user_agent: str = "JordanSec/0.1 (+https://example.local)",
) -> CookiesAuditResult:
    url = normalize_url(target)
    parsed = urlparse(url)
    https = parsed.scheme.lower() == "https"

    result = CookiesAuditResult(
        url=url,
        final_url=url,
        https=https,
        status_code=None,
        cookies_seen=0,
        issues=[],
        warnings=[],
    )

    headers_req = {"User-Agent": user_agent}
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=headers_req,
            verify=verify_tls,
        )
        result.status_code = r.status_code
        result.final_url = r.url or url
        final_https = urlparse(result.final_url).scheme.lower() == "https"
        result.https = final_https

        # Collect Set-Cookie headers (can be multiple)
        set_cookie_headers: List[str] = []
        try:
            set_cookie_headers = r.raw.headers.get_all("Set-Cookie")  # type: ignore[attr-defined]
        except Exception:
            sc = r.headers.get("Set-Cookie")
            if sc:
                # أحياناً بيوصلوا مدموجين، نخليها كـ واحد
                set_cookie_headers = [sc]

        # Parse cookies by looking at Set-Cookie header strings
        issues: List[CookieIssue] = []
        cookies_seen = 0

        for sc in set_cookie_headers:
            if not sc:
                continue
            cookies_seen += 1
            parts = [p.strip() for p in sc.split(";") if p.strip()]
            if not parts:
                continue

            name_part = parts[0]
            name = name_part.split("=", 1)[0].strip() if "=" in name_part else name_part.strip()
            attrs = {p.lower(): p for p in parts[1:]}  # map lower->original

            cookie_issues: List[str] = []

            # Secure
            if "secure" not in attrs:
                cookie_issues.append("Missing Secure")

            # HttpOnly
            if "httponly" not in attrs:
                cookie_issues.append("Missing HttpOnly")

            # SameSite
            has_samesite = any(k.startswith("samesite") for k in attrs.keys())
            if not has_samesite:
                cookie_issues.append("Missing SameSite")

            # If SameSite present but weak config
            for k, orig in attrs.items():
                if k.startswith("samesite"):
                    # orig may be like "SameSite=Lax"
                    if "=" in orig:
                        val = orig.split("=", 1)[1].strip().lower()
                        if val not in {"lax", "strict", "none"}:
                            cookie_issues.append(f"Invalid SameSite value: {val}")
                        if val == "none" and "secure" not in attrs:
                            cookie_issues.append("SameSite=None without Secure")

            if cookie_issues:
                issues.append(CookieIssue(name=name or "(unknown)", issues=cookie_issues))

        result.cookies_seen = cookies_seen
        result.issues = issues

        # Warnings summary
        if not set_cookie_headers and len(r.cookies) == 0:
            result.warnings.append("No cookies detected (no Set-Cookie headers).")
        if not result.https:
            result.warnings.append("Final URL is not HTTPS; cookies are at higher risk.")

        issues_count = sum(len(i.issues) for i in issues)
        result.score = _calc_score(result.https, issues_count, cookies_seen)

        return result

    except Exception as e:
        result.error = str(e)
        return result


def score_cookies(res: CookiesAuditResult) -> Tuple[int, str]:
    s = res.score
    if s >= 90:
        return s, "A"
    if s >= 80:
        return s, "B"
    if s >= 65:
        return s, "C"
    if s >= 50:
        return s, "D"
    return s, "F"
