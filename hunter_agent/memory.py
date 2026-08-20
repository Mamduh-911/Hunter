# -*- coding: utf-8 -*-
"""Central knowledge base, findings, hypotheses and verification history."""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set
from datetime import datetime
import hashlib
import threading


STATUS_ORDER = {
    "confirmed": 0, "likely": 1, "inconclusive": 2,
    "candidate": 3, "false_positive": 4,
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Evidence:
    kind: str
    description: str
    observed: bool = True
    strength: int = 0
    data: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self):
        return asdict(self)


@dataclass
class VerificationAttempt:
    verifier: str
    status: str
    reason: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finished_at: str = ""

    def to_dict(self):
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


@dataclass
class Finding:
    type: str
    severity: str
    url: str
    evidence: str
    description: str
    parameter: str = ""
    status: str = "candidate"
    confidence: str = "low"
    verified: bool = False
    verification_score: int = 0
    reason: str = ""
    poc: str = ""
    evidence_items: List[Evidence] = field(default_factory=list)
    verification_attempts: List[VerificationAttempt] = field(default_factory=list)

    def fingerprint(self) -> str:
        raw = "|".join([self.type, self.url, self.parameter, self.evidence[:120]])
        return hashlib.sha256(raw.encode()).hexdigest()

    def add_evidence(self, evidence: Evidence):
        self.evidence_items.append(evidence)

    def add_attempt(self, attempt: VerificationAttempt):
        self.verification_attempts.append(attempt)

    def decide(self, status: str, confidence: str, score: int, reason: str):
        self.status = status
        self.confidence = confidence
        self.verification_score = max(0, min(100, score))
        self.reason = reason
        self.verified = status == "confirmed"


@dataclass
class Hypothesis:
    vuln_type: str
    target: str
    reasoning: str
    priority: int = 3
    parameter: str = ""
    state: str = "open"


@dataclass
class KnowledgeBase:
    target: str = ""
    urls: Set[str] = field(default_factory=set)
    subdomains: Set[str] = field(default_factory=set)
    js_files: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    verification_log: List[dict] = field(default_factory=list)
    _seen: Set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_url(self, url):
        with self._lock:
            self.urls.add(url)

    def add_finding(self, finding: Finding) -> bool:
        fp = finding.fingerprint()
        with self._lock:
            existing = next((f for f in self.findings if f.fingerprint() == fp), None)
            if existing:
                existing.evidence_items.extend(finding.evidence_items)
                existing.verification_attempts.extend(finding.verification_attempts)
                if finding.verification_score > existing.verification_score:
                    existing.verification_score = finding.verification_score
                if finding.status != "candidate":
                    existing.decide(finding.status, finding.confidence,
                                    finding.verification_score, finding.reason)
                return False
            self._seen.add(fp)
            self.findings.append(finding)
            return True

    def get_finding(self, fingerprint):
        return next((f for f in self.findings if f.fingerprint() == fingerprint), None)

    def add_hypothesis(self, hypothesis: Hypothesis):
        key = (hypothesis.vuln_type, hypothesis.target, hypothesis.parameter)
        with self._lock:
            if any((h.vuln_type, h.target, h.parameter) == key for h in self.hypotheses):
                return False
            self.hypotheses.append(hypothesis)
            return True

    def pending_findings(self):
        return [f for f in self.findings if f.status in {"candidate", "likely", "inconclusive"}]

    def sorted_findings(self):
        return sorted(
            self.findings,
            key=lambda f: (
                STATUS_ORDER.get(f.status, 9),
                SEVERITY_ORDER.get(f.severity, 9),
                -f.verification_score,
            ),
        )

    def summary_for_llm(self, max_findings=30):
        lines = [
            f"الهدف: {self.target}",
            f"URLs={len(self.urls)} subdomains={len(self.subdomains)} "
            f"JS={len(self.js_files)} endpoints={len(self.endpoints)}",
            f"التقنيات: {', '.join(self.technologies[:15]) or 'غير معروفة'}",
            f"النتائج={len(self.findings)} pending={len(self.pending_findings())}",
        ]
        for f in self.sorted_findings()[:max_findings]:
            lines.append(
                f"- [{f.severity}/{f.status}/{f.confidence}/{f.verification_score}] "
                f"{f.type} {f.url} {f.parameter} :: {f.description[:120]}"
            )
        return "\n".join(lines)

    def to_dict(self):
        return {
            "target": self.target,
            "urls": sorted(self.urls),
            "subdomains": sorted(self.subdomains),
            "js_files": sorted(self.js_files),
            "endpoints": sorted(self.endpoints),
            "parameters": self.parameters,
            "technologies": self.technologies,
            "findings": [
                {
                    **asdict(f),
                    "evidence_items": [e.to_dict() for e in f.evidence_items],
                    "verification_attempts": [a.to_dict() for a in f.verification_attempts],
                }
                for f in self.sorted_findings()
            ],
            "hypotheses": [asdict(h) for h in self.hypotheses],
            "notes": self.notes,
            "verification_log": self.verification_log[-200:],
        }
