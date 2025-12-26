from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 10

SEC_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": "Missing CSP can allow XSS attacks",
    "Strict-Transport-Security": "HSTS not enabled",
    "X-Frame-Options": "Missing clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection missing",
    "Referrer-Policy": "Referrer policy not set",
    "Permissions-Policy": "Permissions policy missing",
}


@dataclass
class HeadersAuditResult:
    url: str
    https: bool
    present: Dict[str, str]
    missing: List[str]
    warnings: List[str]
    server: Optional[str] = None
    status_code: Optional[int] = None
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


def _calc_score(missing: List[str], https: bool) -> int:
    # 100 - (كل هيدر ناقص 12 نقطة) - (عدم HTTPS 20 نقطة)
    score = 100
    score -= len(missing) * 12
    if not https:
        score -= 20
    return max(0, min(100, score))


def audit_headers(
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = "JordanSec/0.1 (+https://example.local)",
) -> HeadersAuditResult:
    url = normalize_url(target)
    parsed = urlparse(url)
    https = parsed.scheme.lower() == "https"

    result = HeadersAuditResult(
        url=url,
        https=https,
        present={},
        missing=[],
        warnings=[],
    )

    headers_req = {"User-Agent": user_agent}

    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers_req)
        result.status_code = r.status_code

        resp_headers = {k: v for k, v in r.headers.items()}
        # Server disclosure
        if "Server" in resp_headers:
            result.server = resp_headers.get("Server")
            result.warnings.append(f"Server disclosure: {result.server}")

        # Check common security headers
        for h, msg in SEC_HEADERS.items():
            if h in resp_headers:
                result.present[h] = resp_headers[h]
            else:
                result.missing.append(h)
                result.warnings.append(msg)

        result.score = _calc_score(result.missing, https=result.https)

    except Exception as e:
        result.error = str(e)

    return result


def score_headers(res: HeadersAuditResult) -> Tuple[int, str]:
    """
    Returns: (score, grade)
    """
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
