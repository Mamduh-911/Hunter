# -*- coding: utf-8 -*-
"""Independent consistency check after verification."""
from dataclasses import dataclass


@dataclass
class CriticResult:
    verdict: str
    reason: str


class FindingCritic:
    def review(self, finding):
        if finding.status == "confirmed":
            if not finding.verification_attempts:
                return CriticResult("downgrade", "لا توجد محاولة تحقق مسجلة.")
            if not finding.evidence_items:
                return CriticResult("downgrade", "لا توجد أدلة منظمة.")
            return CriticResult("accept", "النتيجة مدعومة بمحاولة تحقق وأدلة.")
        if finding.status == "likely" and finding.verification_score < 60:
            return CriticResult("downgrade", "درجة الدليل منخفضة لتصنيف likely.")
        return CriticResult("accept", "لا يوجد تعارض مع قواعد الأدلة.")
