from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from jordansc.core.http_client import HttpConfig, build_session, safe_get


SEC_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": "Missing CSP can increase XSS impact.",
    "Strict-Transport-Security": "HSTS not enabled.",
    "X-Frame-Options": "Missing clickjacking protection.",
    "X-Content-Type-Options": "MIME sniffing protection missing.",
    "Referrer-Policy": "Referrer policy not set.",
    "Permissions-Policy": "Permissions-Policy not set.",
}

RECOMMENDED = {
    "X-Content-Type-Options": "nosniff",
    # X-Frame-Options varies per app; we only recommend common safe defaults
}


@dataclass
class CookieFinding:
    name: str
    secure: bool
    httponly: bool
    samesite: Optional[str]


@dataclass
class HeadersAuditResult:
    url: str
    final_url: Optional[str]
    https: bool
    status_code: Optional[int]
    present: Dict[str, str]
    missing: List[str]
    warnings: List[str]
    server: Optional[str]
    cookies: List[CookieFinding]
    score: int
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Empty target")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def _calc_score(missing: List[str], https: bool, cookie_penalty: int) -> int:
    score = 100
    score -= len(missing) * 12
    if not https:
        score -= 20
    score -= cookie_penalty
    return max(0, min(100, score))


def _parse_set_cookie(set_cookie_value: str) -> CookieFinding:
    # Very lightweight parser: "name=value; Secure; HttpOnly; SameSite=Lax"
    parts = [p.strip() for p in set_cookie_value.split(";") if p.strip()]
    name_val = parts[0] if parts else ""
    name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val.strip()

    secure = any(p.lower() == "secure" for p in parts[1:])
    httponly = any(p.lower() == "httponly" for p in parts[1:])
    samesite = None
    for p in parts[1:]:
        if p.lower().startswith("samesite="):
            samesite = p.split("=", 1)[1].strip()
            break

    return CookieFinding(name=name or "(unknown)", secure=secure, httponly=httponly, samesite=samesite)


def audit_headers(
    target: str,
    timeout: int = 10,
    verify_tls: bool = True,
) -> HeadersAuditResult:
    url = normalize_url(target)
    parsed = urlparse(url)
    https = parsed.scheme.lower() == "https"

    cfg = HttpConfig(timeout=timeout, verify_tls=verify_tls)
    session = build_session(cfg)

    r, err = safe_get(session, url, timeout=timeout, verify_tls=verify_tls, allow_redirects=True)
    if err or r is None:
        return HeadersAuditResult(
            url=url,
            final_url=None,
            https=https,
            status_code=None,
            present={},
            missing=list(SEC_HEADERS.keys()),
            warnings=["Request failed."],
            server=None,
            cookies=[],
            score=0,
            error=err or "Request failed",
        )

    resp_headers = {k: v for k, v in r.headers.items()}
    final_url = r.url
    final_https = urlparse(final_url).scheme.lower() == "https"

    present: Dict[str, str] = {}
    missing: List[str] = []
    warnings: List[str] = []
    server = resp_headers.get("Server")

    if server:
        warnings.append(f"Server disclosure: {server}")

    # Check headers presence
    for h, msg in SEC_HEADERS.items():
        if h in resp_headers:
            present[h] = resp_headers[h]
        else:
            missing.append(h)
            warnings.append(msg)

    # Basic value checks
    xcto = resp_headers.get("X-Content-Type-Options", "")
    if xcto and xcto.lower() != RECOMMENDED["X-Content-Type-Options"]:
        warnings.append("X-Content-Type-Options should be 'nosniff'.")

    # Cookies checks
    cookies: List[CookieFinding] = []
    cookie_penalty = 0
    # requests folds multiple Set-Cookie sometimes; handle both
    set_cookie = r.headers.get("Set-Cookie")
    if set_cookie:
        # best-effort split: multiple cookies often separated by comma but commas can appear in expires.
        # We'll just analyze the raw header as one cookie to stay safe.
        cf = _parse_set_cookie(set_cookie)
        cookies.append(cf)
        if not cf.secure:
            cookie_penalty += 5
            warnings.append(f"Cookie '{cf.name}' missing Secure flag.")
        if not cf.httponly:
            cookie_penalty += 5
            warnings.append(f"Cookie '{cf.name}' missing HttpOnly flag.")
        if not cf.samesite:
            cookie_penalty += 3
            warnings.append(f"Cookie '{cf.name}' missing SameSite.")

    score = _calc_score(missing, https=final_https, cookie_penalty=cookie_penalty)

    return HeadersAuditResult(
        url=url,
        final_url=final_url,
        https=final_https,
        status_code=r.status_code,
        present=present,
        missing=missing,
        warnings=warnings,
        server=server,
        cookies=cookies,
        score=score,
        error=None,
    )


def score_headers(res: HeadersAuditResult) -> Tuple[int, str]:
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
