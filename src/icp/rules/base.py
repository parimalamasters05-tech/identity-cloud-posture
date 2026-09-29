"""Rule contract and registry.

A rule reads the normalized tenant and emits findings. It must not touch the
network, the filesystem, or the clock beyond a supplied `now`, which is what
makes the whole rule suite runnable offline against frozen fixtures and
reproducible in CI.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from icp.models.enums import Assessability, CheckFamily, Confidence, Severity
from icp.models.finding import AffectedEntity, Evidence, Finding, build_finding_id
from icp.models.identity import Identity
from icp.normalizers.base import NormalizedTenant
from icp.risk.severity import RiskMatrix


class RuleNotAssessable(Exception):
    """Raised by a rule whose inputs are unknown rather than known-good.

    The engine turns it into a coverage note. Returning an empty list instead
    would read as a pass; guessing a value would read as an observation.
    """

    def __init__(
        self, reason: str, assessability: Assessability = Assessability.NOT_ASSESSABLE_PERMISSION
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.assessability = assessability


@dataclass
class RuleContext:
    """Everything a rule is allowed to depend on, passed explicitly."""

    matrix: RiskMatrix
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    thresholds: dict[str, Any] = field(default_factory=dict)

    def threshold(self, key: str, default: Any) -> Any:
        return self.thresholds.get(key, default)


class Rule(ABC):
    """Base class for every check."""

    rule_id: str = ""
    check_family: CheckFamily
    title: str = ""

    #: Impact and exposure inputs to the matrix. Documented per rule so the
    #: severity is arguable on its merits rather than asserted.
    impact: int = 3
    exposure: int = 3

    remediation_key: str = ""
    framework_refs: tuple[str, ...] = ()
    default_effort_hours: float = 1.0

    #: Collectors this rule cannot run without, beyond what its family needs.
    #: A degraded collector listed here skips this rule alone, with a coverage
    #: note, instead of silencing every rule in the family.
    requires_collectors: tuple[str, ...] = ()

    @abstractmethod
    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        """Return findings. An empty list means the check passed."""

    # -- helpers ---------------------------------------------------------------

    def severity(
        self, ctx: RuleContext, *, impact: int | None = None, exposure: int | None = None
    ) -> Severity:
        return ctx.matrix.severity(impact or self.impact, exposure or self.exposure)

    def make_finding(
        self,
        tenant: NormalizedTenant,
        ctx: RuleContext,
        *,
        title: str,
        entities: Iterable[AffectedEntity],
        evidence: Iterable[Evidence],
        severity: Severity | None = None,
        confidence: Confidence = Confidence.CONFIRMED,
        discriminator: str = "",
        impact: int | None = None,
        exposure: int | None = None,
        effort_hours: float | None = None,
    ) -> Finding:
        entity_tuple = tuple(entities)
        return Finding(
            finding_id=build_finding_id(
                platform=tenant.platform,
                rule_id=self.rule_id,
                discriminator=discriminator,
            ),
            rule_id=self.rule_id,
            platform=tenant.platform,
            check_family=self.check_family,
            title=title,
            severity=severity or self.severity(ctx, impact=impact, exposure=exposure),
            confidence=confidence,
            affected_entities=entity_tuple,
            evidence=tuple(evidence),
            remediation_key=self.remediation_key,
            framework_refs=self.framework_refs,
            effort_hours=effort_hours
            or ctx.matrix.effort(self.remediation_key, self.default_effort_hours, items=len(entity_tuple)),
            assessability=Assessability.ASSESSED,
            first_seen=ctx.now,
            last_seen=ctx.now,
        )


def entity_from_identity(identity: Identity) -> AffectedEntity:
    return AffectedEntity(
        id=identity.id,
        kind=identity.kind.value,
        label=identity.label,
        is_privileged=identity.is_privileged,
    )


_REGISTRY: list[type[Rule]] = []


def register(cls: type[Rule]) -> type[Rule]:
    """Decorator. Registration order is irrelevant; ranking sorts the output."""
    if not cls.rule_id:
        raise ValueError(f"{cls.__name__} must define rule_id")
    if any(existing.rule_id == cls.rule_id for existing in _REGISTRY):
        raise ValueError(f"Duplicate rule_id: {cls.rule_id}")
    _REGISTRY.append(cls)
    return cls


def all_rules() -> list[type[Rule]]:
    return list(_REGISTRY)


def rules_for(family: CheckFamily) -> list[type[Rule]]:
    return [r for r in _REGISTRY if r.check_family == family]


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    """`3 accounts` / `1 account`.

    Finding titles are read aloud in walkthrough calls and quoted in board
    papers. "1 administrator account(s)" undermines a document whose whole value
    proposition is that it reads like it was written by a person.
    """
    word = singular if count == 1 else (plural_form or f"{singular}s")
    return f"{count} {word}"
