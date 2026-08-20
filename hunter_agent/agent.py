# -*- coding: utf-8 -*-
"""Autonomous planner/executor/critic loop."""
import json
import logging
from .critic import FindingCritic
from .llm import LLMClient, extract_json
from .memory import Hypothesis
from .tools import TOOL_DESCRIPTIONS_TEXT
from .verification import VerificationEngine

log = logging.getLogger("HUNTER.agent")

SYSTEM = """أنت HUNTER v6، وكيل أمن تطبيقات ضمن نطاق مصرح به.
هدفك إدارة دورة: observe -> hypothesize -> verify -> inspect evidence -> critic -> repeat.
لا تقل CONFIRMED من رأيك؛ القرار النهائي يأتي من Evidence + Decision Engine.
لا تنفذ عمليات مدمرة أو تغير بيانات.
أرجع JSON فقط من أحد الأنواع:
{"action":"verify_pending","limit":5}
{"action":"verify","fingerprint":"..."}
{"action":"hypothesize","hypotheses":[{"vuln_type":"","target":"","parameter":"","priority":1,"reasoning":""}]}
{"action":"done","summary":""}
الأدوات المتاحة:
""" + TOOL_DESCRIPTIONS_TEXT


class SecurityAgent:
    def __init__(self, ctx):
        self.ctx = ctx
        self.verifier = VerificationEngine(ctx)
        self.critic = FindingCritic()
        self.llm = None
        if ctx.config.llm_enabled:
            self.llm = LLMClient(
                ctx.config.llm_base_url, ctx.config.llm_api_key,
                ctx.config.llm_model, ctx.config.llm_temperature,
                ctx.config.llm_max_tokens
            )
        self.history = []

    def run(self):
        initial = self.verifier.verify_pending(self.ctx.config.auto_verify_limit)
        self._critic()

        if not self.llm:
            self._deterministic_pass()
            return {"mode": "deterministic", "steps": len(initial),
                    "summary": self._summary(), "verification": initial}

        self.history = [{"role": "system", "content": SYSTEM}]
        steps = 0
        for _ in range(self.ctx.config.max_iterations):
            steps += 1
            prompt = (
                self.ctx.kb.summary_for_llm() +
                "\nFingerprints المعلقة:\n" +
                json.dumps([f.fingerprint() for f in self.ctx.kb.pending_findings()[:20]])
            )
            self.history.append({"role": "user", "content": prompt})
            raw = self.llm.chat(self.history, json_mode=True)
            decision = extract_json(raw or "")
            if not decision:
                break
            self.history.append({"role": "assistant", "content": raw})

            action = decision.get("action")
            if action == "done":
                break
            if action == "verify_pending":
                self.verifier.verify_pending(
                    min(int(decision.get("limit", 5)), self.ctx.config.auto_verify_limit)
                )
            elif action == "verify":
                finding = self.ctx.kb.get_finding(decision.get("fingerprint", ""))
                if finding:
                    self.verifier.verify(finding)
            elif action == "hypothesize":
                for item in decision.get("hypotheses", [])[:8]:
                    self.ctx.kb.add_hypothesis(Hypothesis(
                        vuln_type=str(item.get("vuln_type", "unknown")),
                        target=str(item.get("target", "")),
                        reasoning=str(item.get("reasoning", "")),
                        priority=int(item.get("priority", 3)),
                        parameter=str(item.get("parameter", "")),
                    ))
            self._critic()

        self._critic()
        return {"mode": "llm-agent", "steps": steps,
                "summary": self._summary(), "verification": initial}

    def _deterministic_pass(self):
        for finding in self.ctx.kb.pending_findings()[:self.ctx.config.auto_verify_limit]:
            if not finding.verification_attempts:
                self.verifier.verify(finding)
        self._critic()

    def _critic(self):
        for finding in self.ctx.kb.findings:
            review = self.critic.review(finding)
            if review.verdict == "downgrade" and finding.status == "confirmed":
                finding.decide("likely", "medium", min(finding.verification_score, 79),
                               review.reason)

    def _summary(self):
        counts = {}
        for finding in self.ctx.kb.findings:
            counts[finding.status] = counts.get(finding.status, 0) + 1
        return " | ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "لا توجد نتائج."
