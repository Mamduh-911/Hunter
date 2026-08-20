# -*- coding: utf-8 -*-
"""Shared HTTP client: scope, rate limiting, proxy and safe defaults."""
import logging
import time
from typing import Optional
import requests
import urllib3
from .scope import ScopeGuard

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("HUNTER.http")

USER_AGENT = "HUNTER/6.0 (authorized-security-research)"


class HttpClient:
    def __init__(self, scope: ScopeGuard, proxy: Optional[str], delay: float,
                 timeout: int, verify_ssl: bool = False):
        self.scope = scope
        self.delay = max(0.0, delay)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def request(self, method: str, url: str, **kwargs):
        self.scope.enforce(url)
        time.sleep(self.delay)
        kwargs.setdefault("timeout", self.timeout)
        return self.session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs):
        try:
            return self.request("GET", url, **kwargs)
        except Exception as exc:
            log.debug("GET failed: %s", exc)
            return None

    def head(self, url: str, **kwargs):
        try:
            return self.request("HEAD", url, **kwargs)
        except Exception as exc:
            log.debug("HEAD failed: %s", exc)
            return None
