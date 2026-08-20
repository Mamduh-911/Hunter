# -*- coding: utf-8 -*-
"""JavaScript/source-map analysis."""
import concurrent.futures
import re
from urllib.parse import urljoin
from ..memory import Finding

SECRET_PATTERNS = {
    "aws_access_key": (r"AKIA[0-9A-Z]{16}", "high"),
    "google_api_key": (r"AIza[0-9A-Za-z_-]{35}", "high"),
    "github_token": (r"gh[pousr]_[A-Za-z0-9_]{36,255}", "critical"),
    "gitlab_token": (r"glpat-[A-Za-z0-9_-]{20,}", "critical"),
    "slack_token": (r"xox[baprs]-[A-Za-z0-9-]{10,}", "high"),
    "stripe_live_key": (r"(?:sk|rk)_live_[0-9A-Za-z]{16,}", "critical"),
    "jwt_token": (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "medium"),
}
ENDPOINT_RE = re.compile(r"""['"`]((?:https?://|/)[^'"`\s<>]{2,})['"`]""")
SOURCEMAP_RE = re.compile(r"//# sourceMappingURL=([^\s]+)")


def _mask(value):
    return value if len(value) <= 10 else f"{value[:4]}...{value[-4:]} (len={len(value)})"


def _analyze(ctx, source_url, text):
    stats = {"secrets": 0, "endpoints": 0}
    for name, (pattern, severity) in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, text):
            ctx.kb.add_finding(Finding(
                f"exposed_{name}", severity, source_url, _mask(match.group(0)),
                f"مؤشر {name} مكشوف في JavaScript؛ يلزم التحقق من الصلاحية."
            ))
            stats["secrets"] += 1
    for match in ENDPOINT_RE.finditer(text):
        endpoint = match.group(1)
        if any(x in endpoint.lower() for x in (".png", ".jpg", ".svg", ".css", "fonts")):
            continue
        absolute = urljoin(source_url, endpoint)
        if endpoint.startswith("/") or ctx.scope.is_allowed(absolute):
            ctx.kb.endpoints.add(endpoint)
            stats["endpoints"] += 1
    return stats


def analyze_javascript(ctx):
    if not ctx.kb.js_files:
        response = ctx.http.get(ctx.config.target)
        if response:
            for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']',
                                  response.text, re.I):
                absolute = urljoin(ctx.config.target, src)
                if ctx.scope.is_allowed(absolute):
                    ctx.kb.js_files.add(absolute)

    def work(url):
        response = ctx.http.get(url)
        if not response or not response.ok:
            return None
        return _analyze(ctx, url, response.text[:2_000_000])

    stats = {"js_analyzed": 0, "secrets": 0, "endpoints": 0}
    with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.max_workers) as pool:
        for result in pool.map(work, list(ctx.kb.js_files)[:ctx.config.max_targets]):
            if result:
                stats["js_analyzed"] += 1
                stats["secrets"] += result["secrets"]
                stats["endpoints"] += result["endpoints"]
    return stats
