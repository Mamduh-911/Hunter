# -*- coding: utf-8 -*-
"""Low-noise reconnaissance."""
import concurrent.futures
import re
import shutil
import subprocess
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qsl


def _external(command, timeout=120):
    if not shutil.which(command[0]):
        return []
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return [x.strip() for x in p.stdout.splitlines() if x.strip()]
    except Exception:
        return []


def _is_ip_or_local(host):
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)) or host == "localhost"


def _extract_params(ctx, url):
    query = dict(parse_qsl(urlparse(url).query))
    if not query:
        return
    base = url.split("?", 1)[0]
    ctx.kb.parameters.setdefault(base, [])
    for name in query:
        if name not in ctx.kb.parameters[base]:
            ctx.kb.parameters[base].append(name)


def subdomain_enum(ctx):
    host = urlparse(ctx.config.target).hostname or ""
    if _is_ip_or_local(host):
        return {"count": 0, "subdomains": []}
    found = set()
    try:
        import requests
        r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=30)
        if r.ok:
            for row in r.json():
                for name in row.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(host) and ctx.scope.is_allowed("https://" + name):
                        found.add(name)
    except Exception:
        pass
    for command in (["subfinder", "-d", host, "-silent"],
                    ["assetfinder", "--subs-only", host]):
        for name in _external(command):
            name = name.lower().lstrip("*.")
            if name.endswith(host) and ctx.scope.is_allowed("https://" + name):
                found.add(name)
    ctx.kb.subdomains.update(found)
    for name in list(found)[:ctx.config.max_targets]:
        ctx.kb.add_url("https://" + name)
    return {"count": len(found), "subdomains": sorted(found)[:100]}


def wayback_urls(ctx, limit=300):
    host = urlparse(ctx.config.target).netloc
    found = set()
    try:
        import requests
        api = f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=json&collapse=urlkey&limit={limit}"
        r = requests.get(api, timeout=60)
        if r.ok:
            for row in r.json()[1:]:
                if len(row) > 2 and ctx.scope.is_allowed(row[2]):
                    found.add(row[2])
    except Exception:
        pass
    for url in _external(["waybackurls", host]):
        if ctx.scope.is_allowed(url):
            found.add(url)
    for url in found:
        ctx.kb.add_url(url)
        _extract_params(ctx, url)
    return {"count": len(found), "sample": sorted(found)[:50]}


class Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.scripts = set()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.add(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.add(a["src"])
        elif tag == "link" and a.get("href"):
            self.links.add(a["href"])
        elif tag == "form":
            self.forms.append(a)


def crawl_site(ctx, max_pages=20):
    queue = [ctx.config.target]
    visited = set()
    forms = []
    while queue and len(visited) < min(max_pages, ctx.config.max_targets):
        url = queue.pop(0)
        if url in visited or not ctx.scope.is_allowed(url):
            continue
        visited.add(url)
        response = ctx.http.get(url)
        if not response or "text/html" not in response.headers.get("Content-Type", ""):
            continue
        parser = Parser()
        try:
            parser.feed(response.text[:500_000])
        except Exception:
            continue

        for ref in parser.links | parser.scripts:
            absolute = urljoin(url, ref)
            if not ctx.scope.is_allowed(absolute):
                continue
            ctx.kb.add_url(absolute)
            _extract_params(ctx, absolute)
            if urlparse(absolute).path.endswith(".js"):
                ctx.kb.js_files.add(absolute)
            elif "#" not in absolute and absolute not in visited and len(queue) < max_pages:
                queue.append(absolute)

        for form in parser.forms:
            action = urljoin(url, form.get("action", url))
            if ctx.scope.is_allowed(action):
                forms.append({"page": url, "action": action,
                              "method": form.get("method", "GET").upper()})
    return {
        "pages": len(visited),
        "urls": len(ctx.kb.urls),
        "forms": forms[:50],
        "js_files": len(ctx.kb.js_files),
    }
