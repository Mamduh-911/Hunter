# -*- coding: utf-8 -*-
"""Strict scope enforcement."""
import logging
from urllib.parse import urlparse

log = logging.getLogger("HUNTER.scope")


class OutOfScopeError(Exception):
    pass


class ScopeGuard:
    def __init__(self, target: str, extra_scope=None):
        self.allowed_hosts = set()
        self._add(target)
        for item in extra_scope or []:
            self._add(item)
        if not self.allowed_hosts:
            raise ValueError("لم يتم تحديد نطاق صالح.")

    def _add(self, value: str):
        parsed = urlparse(value if "://" in value else f"https://{value}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if host:
            self.allowed_hosts.add(host)

    def is_allowed(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().rstrip(".")
        except Exception:
            return False
        if parsed.scheme not in {"http", "https"} or not host:
            return False
        return any(host == allowed or host.endswith("." + allowed)
                   for allowed in self.allowed_hosts)

    def enforce(self, url: str) -> str:
        if not self.is_allowed(url):
            raise OutOfScopeError(f"طلب مرفوض خارج النطاق: {url}")
        return url

    def describe(self) -> str:
        return ", ".join(sorted(self.allowed_hosts))
