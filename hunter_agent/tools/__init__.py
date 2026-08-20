# -*- coding: utf-8 -*-
"""Tool registry."""
from . import recon, web_scan, js_analysis, verify

TOOLS = {
    "subdomain_enum": (recon.subdomain_enum, "Passive subdomain enumeration.", "recon"),
    "wayback_urls": (recon.wayback_urls, "Collect historical in-scope URLs.", "recon"),
    "crawl_site": (recon.crawl_site, "Light in-scope crawler.", "recon"),
    "detect_technologies": (web_scan.detect_technologies, "Fingerprint web technologies.", "analysis"),
    "check_security_headers": (web_scan.check_security_headers, "Check security headers.", "analysis"),
    "check_cookies": (web_scan.check_cookies, "Check cookie flags.", "analysis"),
    "check_sensitive_files": (web_scan.check_sensitive_files, "Check selected sensitive paths.", "analysis"),
    "analyze_javascript": (js_analysis.analyze_javascript, "Analyze JS for endpoints/secrets.", "analysis"),
    "verify_reflected_xss": (verify.verify_reflected_xss, "Safe reflection check using inert canary.", "verify"),
    "verify_sqli_error": (verify.verify_sqli_error, "Safe SQL error differential check.", "verify"),
    "verify_open_redirect": (verify.verify_open_redirect, "Safe redirect check using example.com.", "verify"),
    "verify_cors": (verify.verify_cors, "CORS Origin reflection check.", "verify"),
}

TOOL_DESCRIPTIONS_TEXT = "\n".join(
    f"- {name}: {desc}" for name, (_, desc, _) in TOOLS.items()
)


def run_tool(ctx, name, args=None):
    if name not in TOOLS:
        return {"ok": False, "error": f"Unknown tool: {name}"}
    fn = TOOLS[name][0]
    try:
        return {"ok": True, "result": fn(ctx, **(args or {}))}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
