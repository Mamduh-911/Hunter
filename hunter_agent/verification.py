# -*- coding: utf-8 -*-
"""Verification orchestrator and evidence extraction."""
from datetime import datetime
from .decision import decide, apply_decision
from .memory import Evidence, VerificationAttempt
from .tools import run_tool

VERIFY_MAP = {
    "xss_reflected": "verify_reflected_xss",
    "xss_candidate": "verify_reflected_xss",
    "sqli_error_based": "verify_sqli_error",
    "sqli_candidate": "verify_sqli_error",
    "open_redirect": "verify_open_redirect",
    "cors_misconfiguration": "verify_cors",
}


class VerificationEngine:
    def __init__(self, ctx):
        self.ctx = ctx
        self.counts = {}

    def verify(self, finding, force=False):
        tool = VERIFY_MAP.get(finding.type)
        if not tool or not self.ctx.config.active_verification:
            return {"ok": False, "status": "skipped", "reason": "لا يوجد verifier أو التحقق معطل."}

        used = self.counts.get(finding.type, 0)
        if used >= self.ctx.config.max_verify_per_type and not force:
            return {"ok": False, "status": "rate_limited", "reason": "تم بلوغ حد التحقق."}
        self.counts[finding.type] = used + 1

        attempt = VerificationAttempt(verifier=tool, status="running")
        started = datetime.utcnow().isoformat() + "Z"
        args = {"url": finding.url}
        if finding.parameter:
            args["param"] = finding.parameter

        try:
            result = run_tool(self.ctx, tool, args)
            payload = result.get("result", {})
            evidence = self._extract(finding, payload)
            for item in evidence:
                finding.add_evidence(item)
            decision = decide(finding, evidence)
            apply_decision(finding, decision)

            attempt.status = decision.status
            attempt.reason = decision.reason
            attempt.evidence = evidence
            attempt.finished_at = datetime.utcnow().isoformat() + "Z"
            finding.add_attempt(attempt)

            self.ctx.kb.verification_log.append({
                "finding": finding.fingerprint(),
                "type": finding.type,
                "url": finding.url,
                "status": decision.status,
                "score": decision.score,
                "reason": decision.reason,
                "started_at": started,
                "finished_at": attempt.finished_at,
            })
            return {
                "ok": True,
                "status": decision.status,
                "confidence": decision.confidence,
                "score": decision.score,
                "reason": decision.reason,
                "evidence": [e.to_dict() for e in evidence],
            }
        except Exception as exc:
            attempt.status = "error"
            attempt.reason = str(exc)
            attempt.finished_at = datetime.utcnow().isoformat() + "Z"
            finding.add_attempt(attempt)
            return {"ok": False, "status": "error", "reason": str(exc)}

    def verify_pending(self, limit=None):
        pending = self.ctx.kb.pending_findings()
        if limit:
            pending = pending[:limit]
        return [
            {
                "type": f.type,
                "url": f.url,
                "parameter": f.parameter,
                **self.verify(f),
            }
            for f in pending
        ]

    @staticmethod
    def _extract(finding, payload):
        if not isinstance(payload, dict):
            return [Evidence("raw_result", "نتيجة غير منظمة.", True, 5)]

        out = []
        if finding.type == "open_redirect" and payload.get("verified"):
            out.append(Evidence("external_redirect", payload.get("evidence", ""), True, 45))
        elif finding.type in {"xss_reflected", "xss_candidate"} and payload.get("verified"):
            out.append(Evidence("raw_reflection", payload.get("evidence", ""), True, 35))
            if payload.get("context") == "html":
                out.append(Evidence("context_html", "انعكاس داخل HTML.", True, 30))
        elif finding.type in {"sqli_error_based", "sqli_candidate"} and payload.get("verified"):
            out.append(Evidence("sql_error_delta", payload.get("evidence", ""), True, 35))
            if payload.get("baseline_clean"):
                out.append(Evidence("baseline_clean", "لا يوجد خطأ SQL في baseline.", True, 25))
        elif finding.type == "cors_misconfiguration" and payload.get("verified"):
            if payload.get("acao"):
                out.append(Evidence("evil_origin_reflection",
                                    f"ACAO={payload['acao']}", True, 35))
            if str(payload.get("acac", "")).lower() == "true":
                out.append(Evidence("credentialed_cors",
                                    "ACAC=true", True, 35))

        if payload.get("repeatable"):
            out.append(Evidence("repeatable", "السلوك قابل للتكرار.", True, 10))
        return out
