from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class HttpConfig:
    timeout: int = 10
    retries: int = 3
    backoff_factor: float = 0.6
    user_agent: str = "JordanSec/0.1 (Defensive Audit)"
    verify_tls: bool = True


def build_session(cfg: HttpConfig) -> requests.Session:
    """
    Robust session:
    - Connection pooling (faster for multiple requests)
    - Automatic retries on transient failures
    """
    session = requests.Session()
    session.headers.update({"User-Agent": cfg.user_agent})

    retry = Retry(
        total=cfg.retries,
        connect=cfg.retries,
        read=cfg.retries,
        status=cfg.retries,
        backoff_factor=cfg.backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def jitter_sleep(base_seconds: float) -> None:
    # tiny jitter to avoid thundering herd if batch scanning
    time.sleep(base_seconds + random.uniform(0.0, 0.25))


def safe_get(
    session: requests.Session,
    url: str,
    timeout: int,
    verify_tls: bool,
    allow_redirects: bool = True,
) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        r = session.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify_tls,
        )
        return r, None
    except Exception as e:
        return None, str(e)
