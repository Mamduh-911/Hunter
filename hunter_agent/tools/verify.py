# -*- coding: utf-8 -*-
"""Safe active verification. No destructive exploitation."""
import random
import string
from html import unescape
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "pg::syntaxerror", "sqlite3.operationalerror",
    "microsoft ole db provider for sql server", "ora-01756",
    "sqlstate[", "syntax error",
]


def _canary():
    return "h6x" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)) + "\"'<>"


def _inject(url, param, value):
    parts = urlparse(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    result = []
    for key, old in pairs:
        if key == param:
            result.append((key, value))
            replaced = True
        else:
            result.append((key, old))
    if not replaced:
        result.append((param, value))
    return urlunparse(parts._replace(query=urlencode(result, doseq=True)))


def verify_reflected_xss(ctx, url, param):
    baseline = ctx.http.get(url, allow_redirects=False)
    marker = _canary()
    response = ctx.http.get(_inject(url, param, marker), allow_redirects=False)
    if not response:
        return {"verified": False, "reason": "لا توجد استجابة."}
    body = response.text
    reflected = marker in body
    context = "html" if reflected and any(
        token in body.lower() for token in ("<html", "<body", "<div")
    ) else "unknown"
    return {
        "verified": reflected,
        "evidence": f"raw_reflection={reflected}",
        "context": context,
        "baseline_clean": baseline is not None,
        "repeatable": reflected,
    }


def verify_sqli_error(ctx, url, param):
    baseline = ctx.http.get(url, allow_redirects=False)
    response = ctx.http.get(_inject(url, param, "'"), allow_redirects=False)
    if not response:
        return {"verified": False, "reason": "لا توجد استجابة."}
    body = response.text.lower()
    matched = next((e for e in SQL_ERRORS if e in body), None)
    baseline_body = baseline.text.lower() if baseline else ""
    baseline_error = next((e for e in SQL_ERRORS if e in baseline_body), None)
    return {
        "verified": bool(matched),
        "evidence": f"sql_error={matched or 'none'}",
        "baseline_clean": baseline_error is None,
        "repeatable": bool(matched),
    }


def verify_open_redirect(ctx, url, param):
    target = "https://example.com/"
    response = ctx.http.get(_inject(url, param, target), allow_redirects=False)
    if not response:
        return {"verified": False, "reason": "لا توجد استجابة."}
    location = response.headers.get("Location", "")
    parsed = urlparse(location)
    confirmed = response.status_code in {301, 302, 303, 307, 308} and parsed.hostname == "example.com"
    return {
        "verified": confirmed,
        "status": response.status_code,
        "location": location[:500],
        "evidence": f"HTTP {response.status_code} -> {location[:180]}",
        "repeatable": confirmed,
    }


def verify_cors(ctx, url=None):
    target = url or ctx.config.target
    evil = "https://hunter-cors-check.example"
    response = ctx.http.get(target, headers={"Origin": evil}, allow_redirects=False)
    if not response:
        return {"verified": False, "reason": "لا توجد استجابة."}
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "").lower()
    reflected = acao == evil
    return {
        "verified": reflected or acao == "*",
        "acao": acao,
        "acac": acac,
        "repeatable": reflected or acao == "*",
    }
