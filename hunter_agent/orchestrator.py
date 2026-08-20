# -*- coding: utf-8 -*-
"""Mission lifecycle coordinator."""
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from .agent import SecurityAgent
from .config import HunterConfig
from .http_client import HttpClient
from .memory import KnowledgeBase
from .scope import ScopeGuard
from .tools import run_tool

log = logging.getLogger("HUNTER.core")


@dataclass
class HunterContext:
    config: HunterConfig
    scope: ScopeGuard
    http: HttpClient
    kb: KnowledgeBase
    executed: set = field(default_factory=set)


class Orchestrator:
    def __init__(self, config):
        self.config = config
        self.config.proxy = self._resolve_proxy(config.proxy)
        scope = ScopeGuard(config.target, config.extra_scope)
        http = HttpClient(scope, config.proxy, config.delay, config.timeout, config.verify_ssl)
        kb = KnowledgeBase(target=config.target)
        kb.add_url(config.target)
        self.ctx = HunterContext(config, scope, http, kb)
        self.started_at = datetime.now()

    @staticmethod
    def _resolve_proxy(proxy):
        if not proxy:
            return None
        parsed = urlparse(proxy)
        try:
            with socket.create_connection(
                (parsed.hostname or "127.0.0.1", parsed.port or 8080), timeout=2
            ):
                return proxy
        except OSError:
            return None

    def run(self):
        phases = [
            ("recon", [("subdomain_enum", {}), ("crawl_site", {}), ("wayback_urls", {})]),
            ("analysis", [
                ("detect_technologies", {}),
                ("check_security_headers", {}),
                ("check_cookies", {}),
                ("check_sensitive_files", {}),
                ("analyze_javascript", {}),
            ]),
        ]
        for phase, tools in phases:
            log.info("=== %s ===", phase)
            for name, args in tools:
                result = run_tool(self.ctx, name, args)
                self.ctx.executed.add(name)
                log.info("%s: %s", name, "OK" if result.get("ok") else "FAILED")

        agent_result = SecurityAgent(self.ctx).run()

        from .reporting.report import ReportGenerator
        paths = ReportGenerator(self.ctx, agent_result, self.started_at).generate_all()

        return {
            "mode": agent_result["mode"],
            "agent_steps": agent_result["steps"],
            "agent_summary": agent_result["summary"],
            "findings": len(self.ctx.kb.findings),
            "verified": sum(f.verified for f in self.ctx.kb.findings),
            "confirmed": sum(f.status == "confirmed" for f in self.ctx.kb.findings),
            "likely": sum(f.status == "likely" for f in self.ctx.kb.findings),
            "false_positive": sum(f.status == "false_positive" for f in self.ctx.kb.findings),
            "reports": paths,
        }
