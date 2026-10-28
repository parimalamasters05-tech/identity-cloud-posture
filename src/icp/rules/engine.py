"""Rules engine.

Runs every registered rule against a normalized tenant, scores the results, and
emits explicit "not assessable" findings for check families whose data never
arrived. That last part matters more than it looks: a check that could not run
must never be indistinguishable from a check that passed, or the report quietly
overstates the client's posture.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from icp.models.enums import Assessability, CheckFamily, Confidence, RuleOutcome, Severity
from icp.models.finding import AcceptedException, AffectedEntity, Evidence, Finding, build_finding_id
from icp.normalizers.base import NormalizedTenant
from icp.risk import scoring
from icp.risk.severity import RiskMatrix
from icp.rules.base import Rule, RuleContext, RuleNotAssessable, all_rules
from icp.rules.exceptions import ExceptionsReport
from icp.rules.exceptions import apply as apply_exceptions

logger = logging.getLogger(__name__)


@dataclass
class AssessmentResult:
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    rules_failed: list[tuple[str, str]] = field(default_factory=list)
    unassessable: dict[str, str] = field(default_factory=dict)
    #: Families that ran on incomplete data (gap key -> reason).
    partial_coverage: dict[str, str] = field(default_factory=dict)
    #: rule_id -> what happened to it, for every rule of the tenant's platform.
    #: The report's clean areas are built from this, so a rule that crashed or
    #: never ran can never be shown as passed.
    outcomes: dict[str, RuleOutcome] = field(default_factory=dict)
    #: What the engagement's reviewed exceptions did (see icp.rules.exceptions).
    exceptions: ExceptionsReport = field(default_factory=ExceptionsReport)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def rules_with(self, outcome: RuleOutcome) -> list[str]:
        return sorted(r for r, o in self.outcomes.items() if o == outcome)

    def by_family(self) -> dict[CheckFamily, list[Finding]]:
        grouped: dict[CheckFamily, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.check_family, []).append(finding)
        return grouped

    def counts_by_severity(self) -> dict[str, int]:
        counts = {str(s): 0 for s in Severity}
        for finding in self.findings:
            counts[str(finding.severity)] += 1
        return counts


def assess(
    tenant: NormalizedTenant,
    *,
    matrix: RiskMatrix | None = None,
    thresholds: dict[str, Any] | None = None,
    now: datetime | None = None,
    exceptions: list[AcceptedException] | None = None,
) -> AssessmentResult:
    matrix = matrix or RiskMatrix.load_default()
    ctx = RuleContext(
        matrix=matrix,
        now=now or datetime.now(UTC),
        thresholds=thresholds or {},
    )

    result = AssessmentResult()
    raw: list[Finding] = []
    collector_errors = {e.collector: e for e in tenant.snapshot.errors}

    partial_families = {f for gap in tenant.coverage_gaps for f in gap.families}

    for rule_cls in all_rules():
        rule: Rule = rule_cls()

        if tenant.platform not in rule.platforms:
            continue

        if not tenant.is_assessable(rule.check_family):
            result.outcomes[rule.rule_id] = RuleOutcome.UNAVAILABLE
            continue

        missing = [c for c in rule.requires_collectors if c in collector_errors]
        if missing:
            error = collector_errors[missing[0]]
            raw.append(_rule_not_assessed(tenant, ctx, result, rule, error.assessability, error.message))
            result.outcomes[rule.rule_id] = RuleOutcome.UNAVAILABLE
            continue

        try:
            produced = rule.evaluate(tenant, ctx)
            raw.extend(produced)
            result.rules_run += 1
            if produced:
                result.outcomes[rule.rule_id] = RuleOutcome.FINDING
            elif rule.check_family in partial_families:
                result.outcomes[rule.rule_id] = RuleOutcome.PARTIAL
            else:
                result.outcomes[rule.rule_id] = RuleOutcome.PASSED
        except RuleNotAssessable as exc:
            raw.append(_rule_not_assessed(tenant, ctx, result, rule, exc.assessability, exc.reason))
            result.outcomes[rule.rule_id] = RuleOutcome.UNAVAILABLE
        except Exception as exc:
            logger.exception("Rule %s raised", rule.rule_id)
            error_text = f"{type(exc).__name__}: {exc}"
            result.rules_failed.append((rule.rule_id, error_text))
            result.outcomes[rule.rule_id] = RuleOutcome.FAILED
            # Said in the report, not only in a log line: a check that crashed must
            # never read as one that passed (review, 27 Oct 2026).
            raw.append(_rule_failed(tenant, ctx, rule, error_text))

    raw.extend(_unassessable_findings(tenant, ctx, result))
    raw.extend(_partial_coverage_findings(tenant, ctx, result))
    result.findings = scoring.apply(raw, matrix)
    # After scoring: an exception changes what is acted on, not what was found.
    if exceptions:
        result.findings, result.exceptions = apply_exceptions(result.findings, exceptions, ctx.now)
    return result


def _partial_coverage_findings(
    tenant: NormalizedTenant, ctx: RuleContext, result: AssessmentResult
) -> list[Finding]:
    """One informational note per family that ran on incomplete data."""
    findings: list[Finding] = []
    for gap in tenant.coverage_gaps:
        assessed = [f for f in gap.families if tenant.is_assessable(f)]
        if not assessed:
            continue  # already reported as not assessed at all
        result.partial_coverage[gap.key] = gap.reason

        entities = tuple(
            AffectedEntity(id=missed_id, kind="user", label=label) for missed_id, label in gap.missed
        ) or (AffectedEntity(id=gap.key, kind="coverage_gap", label=gap.key),)
        area = str(assessed[0]).replace("_", " ")
        findings.append(
            Finding(
                finding_id=build_finding_id(
                    platform=tenant.platform,
                    rule_id="ICP-COVERAGE-003",
                    discriminator=gap.key,
                ),
                rule_id="ICP-COVERAGE-003",
                platform=tenant.platform,
                check_family=assessed[0],
                title=f"Partly assessed: {area}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                affected_entities=entities,
                evidence=(
                    Evidence(
                        collector="icp.coverage",
                        pointer=f"/partial/{gap.key}",
                        summary=(
                            "These checks ran on incomplete data. Their findings stand, but a clean "
                            f"result in this area is not proof that nothing is wrong. Reason: {gap.reason}"
                        ),
                        # Every area the gap touches, for the delta: a finding gone
                        # from any of them was not fully rechecked.
                        observed_values={
                            "missed": len(gap.missed),
                            "families": ",".join(str(f) for f in assessed),
                        },
                    ),
                ),
                remediation_key="coverage.restore_access",
                effort_hours=0.5,
                assessability=Assessability.ASSESSED,
                first_seen=ctx.now,
                last_seen=ctx.now,
            )
        )
    return findings


def _rule_not_assessed(
    tenant: NormalizedTenant,
    ctx: RuleContext,
    result: AssessmentResult,
    rule: Rule,
    assessability: Assessability,
    reason: str,
) -> Finding:
    """A coverage note for one rule whose data never arrived, while its family ran."""
    result.unassessable[rule.rule_id] = reason
    entity = AffectedEntity(id=rule.rule_id, kind="rule", label=rule.title)
    return Finding(
        finding_id=build_finding_id(
            platform=tenant.platform,
            rule_id="ICP-COVERAGE-002",
            discriminator=rule.rule_id,
        ),
        rule_id="ICP-COVERAGE-002",
        platform=tenant.platform,
        check_family=rule.check_family,
        title=f"Not assessed: {rule.title[0].lower()}{rule.title[1:]}",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        affected_entities=(entity,),
        evidence=(
            Evidence(
                collector="icp.coverage",
                pointer="/errors",
                summary=(
                    "This one check could not be evaluated; the other checks in its area ran "
                    f"normally. Its absence from the findings list is not a pass. Reason: {reason}"
                ),
                observed_values={"assessability": str(assessability), "rule_id": rule.rule_id},
            ),
        ),
        remediation_key="coverage.restore_access",
        effort_hours=0.5,
        assessability=assessability,
        first_seen=ctx.now,
        last_seen=ctx.now,
    )


def _rule_failed(tenant: NormalizedTenant, ctx: RuleContext, rule: Rule, error: str) -> Finding:
    """A coverage note for one rule that raised: it says nothing either way."""
    entity = AffectedEntity(id=rule.rule_id, kind="rule", label=rule.title)
    return Finding(
        finding_id=build_finding_id(
            platform=tenant.platform,
            rule_id="ICP-COVERAGE-004",
            discriminator=rule.rule_id,
        ),
        rule_id="ICP-COVERAGE-004",
        platform=tenant.platform,
        check_family=rule.check_family,
        title=f"Check failed: {rule.title[0].lower()}{rule.title[1:]}",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        affected_entities=(entity,),
        evidence=(
            Evidence(
                collector="icp.coverage",
                pointer="/rules_failed",
                summary=(
                    "This check stopped with an error in the assessment tool, so nothing is known about "
                    "what it covers. Its absence from the findings list is not a pass, and its area is "
                    f"not listed as clean. Error: {error}"
                ),
                observed_values={"rule_id": rule.rule_id},
            ),
        ),
        remediation_key="coverage.rule_failed",
        effort_hours=0.5,
        assessability=Assessability.ASSESSED,
        first_seen=ctx.now,
        last_seen=ctx.now,
    )


def _unassessable_findings(
    tenant: NormalizedTenant, ctx: RuleContext, result: AssessmentResult
) -> list[Finding]:
    """One informational finding per check family that could not be assessed."""
    findings: list[Finding] = []

    for family, (assessability, reason) in tenant.assessability.items():
        if assessability == Assessability.ASSESSED:
            continue
        result.unassessable[str(family)] = reason

        entity = AffectedEntity(id=str(family), kind="check_family", label=str(family))
        findings.append(
            Finding(
                finding_id=build_finding_id(
                    platform=tenant.platform,
                    rule_id="ICP-COVERAGE-001",
                    discriminator=str(family),
                ),
                rule_id="ICP-COVERAGE-001",
                platform=tenant.platform,
                check_family=family,
                title=f"Not assessed: {str(family).replace('_', ' ')}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                affected_entities=(entity,),
                evidence=(
                    Evidence(
                        collector="icp.coverage",
                        pointer="/errors",
                        summary=(
                            "This check family could not be evaluated, so its absence from the "
                            f"findings list is not a pass. Reason: {reason}"
                        ),
                        observed_values={"assessability": str(assessability)},
                    ),
                ),
                remediation_key="coverage.restore_access",
                effort_hours=0.5,
                assessability=assessability,
                first_seen=ctx.now,
                last_seen=ctx.now,
            )
        )
    return findings
