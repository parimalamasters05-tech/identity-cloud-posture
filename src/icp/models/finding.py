"""The normalized finding model -- the single object every rule emits.

Finding IDs are deterministic: the same misconfiguration produces the same ID
on every run, forever, however many accounts it affects this quarter. Quarterly delta reporting depends
entirely on this property, and it is cheap now and expensive to retrofit later,
so it is enforced by `tests/rules/test_finding_id_stability.py`.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from icp.models.enums import (
    Assessability,
    CheckFamily,
    Confidence,
    FindingStatus,
    Platform,
    Severity,
)

#: v2: IDs no longer depend on the affected-entity set. Findings files record
#: this, and the delta refuses to compare across versions.
ID_NAMESPACE = "icp.finding.v2"


class AffectedEntity(BaseModel):
    """An entity a finding is about. Privilege drives a scoring modifier."""

    model_config = ConfigDict(frozen=True)

    id: str
    kind: str
    label: str
    is_privileged: bool = False

    def key(self) -> str:
        """Identity of this entity across runs, for the delta's membership diff.

        Excludes `label` and `is_privileged`: a user renaming themselves, or
        gaining admin, is the same member.
        """
        return f"{self.kind}:{self.id}"


class Evidence(BaseModel):
    """Pointer back into the snapshot that produced this finding.

    `pointer` is a JSON-pointer-style path into the snapshot artifact, so a
    skeptical IT contact can be walked from a sentence in the report to the exact
    API response that justified it.
    """

    model_config = ConfigDict(frozen=True)

    collector: str
    pointer: str
    summary: str
    observed_values: dict[str, str | int | float | bool | None] = {}


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_id: str
    rule_id: str
    platform: Platform
    check_family: CheckFamily

    title: str
    severity: Severity
    confidence: Confidence

    affected_entities: tuple[AffectedEntity, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    remediation_key: str
    framework_refs: tuple[str, ...] = ()

    risk_score: float = 0.0
    effort_hours: float = 0.5
    assessability: Assessability = Assessability.ASSESSED

    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: FindingStatus | None = None

    @property
    def entity_count(self) -> int:
        return len(self.affected_entities)

    @property
    def privileged_entity_count(self) -> int:
        return sum(1 for e in self.affected_entities if e.is_privileged)


def build_finding_id(*, platform: Platform, rule_id: str, discriminator: str = "") -> str:
    """Derive a stable finding ID from *which problem* this is.

    Inputs: the rule, and -- for rules that emit one finding per subject -- the
    subject (an OAuth client ID, a coverage family). Nothing else.

    Deliberately not an input: who is affected. v1 hashed the affected-account
    set, so when one of eight accounts without 2SV enrolled, the quarterly
    delta read "1 resolved, 1 new" instead of "still open, 8 -> 7". Membership
    is what a finding's *progress* is measured in, so it cannot also be its
    identity. `icp.delta.compare` reports membership changes per finding.

    Also excluded, as before: severity, scores, counts, timestamps, display names.
    """
    payload = "|".join([ID_NAMESPACE, str(platform), rule_id, discriminator])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
