# -*- coding: utf-8 -*-
"""HTML/JSON reporting."""
from pathlib import Path
from datetime import datetime
import html
import json


class ReportGenerator:
    def __init__(self, ctx, agent_result, started_at):
        self.ctx = ctx
        self.agent_result = agent_result
        self.started_at = started_at
        self.out = Path(ctx.config.report_dir)

    def generate_all(self):
        self.out.mkdir(parents=True, exist_ok=True)
        return {
            "html": str(self._html()),
            "json": str(self._json()),
            "targets": str(self._targets()),
        }

    def _json(self):
        data = self.ctx.kb.to_dict()
        data["meta"] = {
            "tool": "HUNTER v6",
            "version": "6.0.0",
            "target": self.ctx.config.target,
            "mode": self.agent_result["mode"],
            "started": self.started_at.isoformat(),
            "finished": datetime.now().isoformat(),
        }
        path = self.out / "findings.json"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _targets(self):
        path = self.out / "hunter_targets.txt"
        path.write_text("\n".join(sorted(self.ctx.kb.urls)), encoding="utf-8")
        return path

    def _html(self):
        findings = self.ctx.kb.sorted_findings()
        esc = html.escape
        rows = []
        for f in findings:
            evidence = "<br>".join(
                esc(e.description) for e in f.evidence_items[-8:]
            ) or "—"
            attempts = "<br>".join(
                f"{esc(a.verifier)} → {esc(a.status)}"
                for a in f.verification_attempts[-5:]
            ) or "—"
            rows.append(
                "<tr>"
                f"<td>{esc(f.severity)}</td><td>{esc(f.status)}</td>"
                f"<td>{esc(f.confidence)}</td><td>{f.verification_score}/100</td>"
                f"<td><code>{esc(f.type)}</code></td>"
                f"<td class='url'>{esc(f.url)}</td><td>{esc(f.parameter)}</td>"
                f"<td>{esc(f.description)}<hr>{esc(f.reason)}</td>"
                f"<td>{evidence}<hr>{attempts}</td>"
                "</tr>"
            )
        path = self.out / "hunter_dashboard.html"
        html_doc = f"""<!doctype html>
<html lang="ar" dir="rtl"><meta charset="utf-8">
<title>HUNTER v6 — Verification Dashboard</title>
<style>
body{{font-family:Segoe UI,Tahoma,sans-serif;background:#0d1117;color:#e6edf3;margin:0}}
header{{padding:28px 32px;border-bottom:1px solid #30363d}}
table{{width:calc(100% - 40px);margin:20px;border-collapse:collapse;font-size:13px}}
th,td{{border:1px solid #30363d;padding:9px;vertical-align:top}}
th{{background:#161b22;position:sticky;top:0}}
.url{{direction:ltr;text-align:left;word-break:break-all;max-width:260px}}
code{{background:#161b22;padding:2px 5px}}
hr{{border:0;border-top:1px solid #30363d}}
</style>
<header>
<h1>👾 HUNTER v6 — Verification Dashboard</h1>
<p>Target: <code>{esc(self.ctx.config.target)}</code></p>
<p>Mode: {esc(self.agent_result["mode"])} | Findings: {len(findings)}</p>
</header>
<table><thead><tr>
<th>Severity</th><th>Status</th><th>Confidence</th><th>Score</th>
<th>Type</th><th>URL</th><th>Parameter</th><th>Decision</th><th>Evidence / Attempts</th>
</tr></thead><tbody>{''.join(rows)}</tbody></table>
"""
        path.write_text(html_doc, encoding="utf-8")
        return path
