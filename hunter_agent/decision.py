# -*- coding: utf-8 -*-
"""Deterministic evidence-based decision engine."""
from dataclasses import dataclass


@dataclass
class Decision:
    status: str
    confidence: str
    score: int
    reason: str


def decide(finding, evidence):
    observed = [e for e in evidence if e.observed]
    kinds = {e.kind for e in observed}
    score = min(100, sum(max(0, min(40, e.strength)) for e in observed))

    if finding.type == "open_redirect" and "external_redirect" in kinds:
        return Decision("confirmed", "high", max(score, 90),
                        "ثبت تحويل خارجي في Location بعد اختبار قيمة محايدة.")

    if finding.type == "cors_misconfiguration":
        if "evil_origin_reflection" in kinds and "credentialed_cors" in kinds:
            return Decision("confirmed", "high", max(score, 90),
                            "Origin غير موثوق انعكس مع السماح بالاعتمادات.")
        if "evil_origin_reflection" in kinds:
            return Decision("likely", "high", max(score, 80),
                            "Origin غير موثوق انعكس؛ الأثر المعتمد يحتاج سياقًا إضافيًا.")

    if finding.type in {"xss_reflected", "xss_candidate"}:
        if "raw_reflection" in kinds and "context_html" in kinds:
            return Decision("likely", "high", max(score, 75),
                            "انعكاس خام داخل HTML، لكن لم يتم اعتبار تنفيذ JavaScript مثبتًا.")
        if "raw_reflection" in kinds:
            return Decision("likely", "medium", max(score, 65),
                            "القيمة تحت سيطرة المستخدم وانعكست خامًا، والسياق التنفيذي غير مثبت.")

    if finding.type in {"sqli_error_based", "sqli_candidate"}:
        if "sql_error_delta" in kinds and "baseline_clean" in kinds:
            return Decision("likely", "high", max(score, 75),
                            "خطأ SQL ظهر بعد الاختبار ولم يظهر في baseline.")

    if score >= 80:
        return Decision("likely", "high", score,
                        "أدلة قوية، لكنها لا تطابق قاعدة تأكيد محددة.")
    if score >= 55:
        return Decision("inconclusive", "medium", score,
                        "أدلة جزئية؛ يلزم تحقق إضافي.")
    return Decision("false_positive", "low", score,
                    "لا توجد أدلة كافية لدعم الفرضية.")


def apply_decision(finding, decision):
    finding.decide(decision.status, decision.confidence,
                   decision.score, decision.reason)
