# -*- coding: utf-8 -*-
"""Passive web checks."""
import re
from urllib.parse import urljoin
from ..memory import Finding

SECURITY_HEADERS = {
    "Content-Security-Policy": ("low", "CSP مفقود"),
    "Strict-Transport-Security": ("low", "HSTS مفقود"),
    "X-Frame-Options": ("medium", "Clickjacking protection غير واضح"),
    "X-Content-Type-Options": ("low", "MIME sniffing protection مفقود"),
    "Referrer-Policy": ("info", "Referrer-Policy مفقود"),
    "Permissions-Policy": ("info", "Permissions-Policy مفقود"),
}
SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/database.sql", "/dump.sql", "/openapi.json", "/swagger.json",
    "/.well-known/security.txt", "/server-status", "/actuator/env",
]
TECH_SIGNATURES = {
    "WordPress": r"wp-content|wp-includes",
    "React": r"react(?:\.production)?\.min\.js|__REACT_DEVTOOLS",
    "Vue.js": r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-",
    "Angular": r"ng-app|angular(?:\.min)?\.js",
    "Next.js": r"_next/static|__NEXT_DATA__",
    "Laravel": r"laravel_session|XSRF-TOKEN",
    "Django": r"csrfmiddlewaretoken",
    "Cloudflare": r"cloudflare",
}


def _urls(ctx, url=None):
    if url:
        return [url] if ctx.scope.is_allowed(url) else []
    return [ctx.config.target] + [u for u in sorted(ctx.kb.urls)[:5]
                                  if ctx.scope.is_allowed(u)]


def check_security_headers(ctx, url=None):
    count = 0
    for target in _urls(ctx, url):
        response = ctx.http.get(target)
        if not response:
            continue
        headers = {k.lower(): v for k, v in response.headers.items()}
        for header, (severity, desc) in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                if header == "X-Frame-Options" and "frame-ancestors" in headers.get("content-security-policy", ""):
                    continue
                if ctx.kb.add_finding(Finding(
                    "missing_security_header", severity, target, header, desc
                )):
                    count += 1
    return {"header_issues": count}


def check_cookies(ctx, url=None):
    count = 0
    for target in _urls(ctx, url):
        response = ctx.http.get(target)
        if not response:
            continue
        raw = response.headers.get("Set-Cookie", "")
        if not raw:
            continue
        for cookie in raw.split(","):
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            if target.startswith("https://") and "secure" not in low:
                ctx.kb.add_finding(Finding(
                    "cookie_no_secure", "medium", target, name,
                    f"الكوكي {name} بدون Secure"
                ))
                count += 1
            if re.search(r"session|token|auth", name, re.I) and "httponly" not in low:
                ctx.kb.add_finding(Finding(
                    "cookie_no_httponly", "medium", target, name,
                    f"الكوكي {name} بدون HttpOnly"
                ))
                count += 1
    return {"cookie_issues": count}


def check_sensitive_files(ctx, url=None):
    base = url or ctx.config.target
    count = 0
    for path in SENSITIVE_PATHS:
        target = urljoin(base, path)
        if not ctx.scope.is_allowed(target):
            continue
        response = ctx.http.get(target, allow_redirects=False)
        if not response or response.status_code not in {200, 401, 403}:
            continue
        if response.status_code in {401, 403}:
            severity = "info"
        elif any(x in path for x in (".env", ".git", ".sql", "actuator/env")):
            severity = "critical"
        else:
            severity = "high"
        if ctx.kb.add_finding(Finding(
            "sensitive_file_exposed", severity, target,
            f"HTTP {response.status_code}",
            f"مسار حساس يستجيب: {path}"
        )):
            count += 1
    return {"sensitive_files": count}


def detect_technologies(ctx):
    response = ctx.http.get(ctx.config.target)
    if not response:
        return {"technologies": []}
    haystack = response.text[:500_000] + " " + " ".join(
        f"{k}:{v}" for k, v in response.headers.items()
    )
    techs = [name for name, pattern in TECH_SIGNATURES.items()
             if re.search(pattern, haystack, re.I)]
    server = response.headers.get("Server") or response.headers.get("X-Powered-By")
    if server:
        techs.append(server)
    for tech in techs:
        if tech not in ctx.kb.technologies:
            ctx.kb.technologies.append(tech)
    return {"technologies": techs}
