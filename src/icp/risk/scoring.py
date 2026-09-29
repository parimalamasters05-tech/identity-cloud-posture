"""Risk scoring.

score = base(severity) x privilege x blast_radius x confidence

Every term is bounded, named, and reproducible, and `explain()` returns the
arithmetic for any finding so the report can show its working. Nothing here is
tuned to make output look good; when a ranking feels wrong, the fix is to change
the matrix in config and say so, not to add an unexplained fudge factor.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from icp.models.enums import Confidence, Severity
from icp.models.finding import Finding
from icp.risk.severity import RiskMatrix

_BASE_SCORE = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 12.0,
    Severity.LOW: 5.0,
    Severity.INFO: 1.0,
}

_CONFIDENCE_FACTOR = {
    Confidence.CONFIRMED: 1.0,
    Confidence.HIGH: 0.95,
    Confidence.MEDIUM: 0.85,
    Confidence.LOW: 0.7,
}


@dataclass(frozen=True)
class ScoreBreakdown:
    """The arithmetic behind one score, rendered in the evidence appendix."""

    base: float
    privilege_modifier: float
    blast_radius_modifier: float
    confidence_factor: float
    total: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "base": round(self.base, 2),
            "privilege_modifier": round(self.privilege_modifier, 2),
            "blast_radius_modifier": round(self.blast_radius_modifier, 2),
            "confidence_factor": round(self.confidence_factor, 2),
            "total": round(self.total, 2),
        }


def privilege_modifier(finding: Finding, matrix: RiskMatrix) -> float:
    """A gap on a super-admin outranks the same gap on a contractor.

    Applied per-finding, not per-entity: one privileged account anywhere in the
    affected set lifts the whole finding, because an attacker only needs one.
    """
    if finding.privileged_entity_count == 0:
        return 1.0
    return matrix.modifier("privileged_entity", 1.6)


def blast_radius_modifier(finding: Finding, matrix: RiskMatrix) -> float:
    """Scale with how many entities are affected -- sub-linearly.

    Logarithmic on purpose. A gap affecting 40 users is worse than one affecting
    4, but it is not ten times worse, and linear scaling would push every
    tenant-wide informational finding above every critical single-account one.
    """
    count = max(finding.entity_count, 1)
    per_entity = matrix.modifier("blast_radius_per_decade", 0.35)
    cap = matrix.modifier("blast_radius_cap", 2.0)
    return min(1.0 + per_entity * math.log10(count), cap)


def score(finding: Finding, matrix: RiskMatrix) -> ScoreBreakdown:
    base = _BASE_SCORE[finding.severity]
    privilege = privilege_modifier(finding, matrix)
    blast = blast_radius_modifier(finding, matrix)
    confidence = _CONFIDENCE_FACTOR[finding.confidence]
    total = base * privilege * blast * confidence
    return ScoreBreakdown(base, privilege, blast, confidence, round(total, 2))


def apply(findings: list[Finding], matrix: RiskMatrix) -> list[Finding]:
    """Return scored copies. Findings are frozen, so this rebuilds them."""
    scored: list[Finding] = []
    for finding in findings:
        breakdown = score(finding, matrix)
        scored.append(finding.model_copy(update={"risk_score": breakdown.total}))
    return scored


def explain(finding: Finding, matrix: RiskMatrix) -> dict[str, Any]:
    """Full arithmetic for one finding, for the appendix and for arguing with."""
    breakdown = score(finding, matrix)
    return {
        "finding_id": finding.finding_id,
        "severity": str(finding.severity),
        "entities": finding.entity_count,
        "privileged_entities": finding.privileged_entity_count,
        "confidence": str(finding.confidence),
        **breakdown.as_dict(),
        "formula": "base x privilege x blast_radius x confidence",
    }
