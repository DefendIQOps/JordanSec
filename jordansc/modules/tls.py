from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

import socket
import ssl


DEFAULT_TIMEOUT = 10


@dataclass
class TLSAuditResult:
    url: str
    host: str
    port: int = 443

    https: bool = False
    tls_version: Optional[str] = None
    cipher: Optional[str] = None

    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_not_before: Optional[str] = None
    cert_not_after: Optional[str] = None
    cert_days_left: Optional[int] = None

    sni: bool = True
    verified: bool = True

    score: int = 0
    error: Optional[str] = None
    warnings: list[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []

    def to_dict(self) -> dict:
        return asdict(self)


def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Empty target")

    if not raw.startswith(("http://", "https://")):
        # TLS audit منطقيًا نفترض https
        raw = "https://" + raw
    return raw


def _calc_score(
    verified: bool,
    has_cert: bool,
    days_left: Optional[int],
    tls_version: Optional[str],
    has_cipher: bool,
    warnings_count: int,
) -> int:
    score = 100

    if not has_cert:
        return 0

    if not verified:
        score -= 35

    if days_left is not None:
        if days_left < 0:
            score -= 90
        elif days_left < 7:
            score -= 35
        elif days_left < 30:
            score -= 15

    # تفضيل TLS 1.3 / 1.2
    if tls_version:
        v = tls_version.upper()
        if "TLSV1.3" in v:
            score += 0
        elif "TLSV1.2" in v:
            score -= 5
        else:
            score -= 30
    else:
        score -= 20

    if not has_cipher:
        score -= 15

    # كل تحذير بسيط ينقص
    score -= min(20, warnings_count * 5)

    if score < 0:
        score = 0
    if score > 100:
        score = 100
    return score


def audit_tls(
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_tls: bool = True,   # <<< هذا هو اللي كان ناقص وسبب الكراش
) -> TLSAuditResult:
    """
    TLS audit:
    - TLS version / cipher
    - Certificate subject/issuer and expiry
    - Optional verify/skip verify using verify_tls
    """
    url = _normalize_url(target)
    parsed = urlparse(url)

    host = parsed.hostname or parsed.path
    if not host:
        raise ValueError("Invalid target host")

    https = parsed.scheme.lower() == "https"

    result = TLSAuditResult(
        url=url,
        host=host,
        port=443,
        https=https,
        verified=verify_tls,
        sni=True,
    )

    # SSL context
    try:
        if verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            result.warnings.append("TLS verification disabled (insecure mode).")

        # نقيّد البروتوكولات الضعيفة (إن أمكن)
        # ملاحظة: على بعض البيئات ممكن ما يدعم TLSVersion، فبنحط try
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            result.warnings.append("Could not enforce minimum TLS version (env limitation).")

        # Socket connect + handshake
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host if result.sni else None) as ssock:
                # negotiated details
                result.tls_version = ssock.version()
                c = ssock.cipher()
                result.cipher = c[0] if c else None

                # cert details (may be None in CERT_NONE mode)
                cert = ssock.getpeercert()
                has_cert = bool(cert)

                if has_cert:
                    # subject / issuer (تحويل بسيط لنص)
                    subj = cert.get("subject", [])
                    issr = cert.get("issuer", [])
                    result.cert_subject = " / ".join("=".join(x) for part in subj for x in part) or None
                    result.cert_issuer = " / ".join("=".join(x) for part in issr for x in part) or None

                    nb = cert.get("notBefore")
                    na = cert.get("notAfter")
                    result.cert_not_before = nb
                    result.cert_not_after = na

                    # parse expiry (صيغة OpenSSL المعتادة)
                    days_left = None
                    if na:
                        try:
                            # مثال: 'Jun  1 12:00:00 2026 GMT'
                            exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_left = (exp - now).days
                            result.cert_days_left = days_left
                            if days_left < 30:
                                result.warnings.append(f"Certificate expires soon: {days_left} days left.")
                        except Exception:
                            result.warnings.append("Could not parse certificate expiry date.")

                # score
                result.score = _calc_score(
                    verified=verify_tls,
                    has_cert=has_cert,
                    days_left=result.cert_days_left,
                    tls_version=result.tls_version,
                    has_cipher=bool(result.cipher),
                    warnings_count=len(result.warnings),
                )

    except ssl.SSLCertVerificationError as e:
        result.error = f"Certificate verification failed: {e}"
        result.warnings.append("Certificate verification failed.")
        result.score = _calc_score(
            verified=False,
            has_cert=True,
            days_left=None,
            tls_version=None,
            has_cipher=False,
            warnings_count=len(result.warnings),
        )
    except Exception as e:
        result.error = str(e)
        result.warnings.append("TLS connection/handshake failed.")
        result.score = 0

    return result


def score_tls(res: TLSAuditResult) -> Tuple[int, str]:
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
