"""Scoring and prioritization.

The arithmetic is printed in the client report, so it has to be defensible and
it has to stay put.
"""

from __future__ import annotations

import pytest

from icp.models.enums import CheckFamily, Confidence, Platform, Severity
from icp.models.finding import AffectedEntity, Finding
from icp.risk import scoring
from icp.risk.ranking import posture_rating, rank, risk_per_hour


def make(
    *,
    severity=Severity.HIGH,
    entities=1,
    privileged=0,
    confidence=Confidence.CONFIRMED,
    effort=1.0,
    remediation_key="mfa.enforce_admins",
    rule_id="R-1",
) -> Finding:
    affected = tuple(
        AffectedEntity(id=str(i), kind="user", label=f"u{i}", is_privileged=i < privileged)
        for i in range(entities)
    )
    return Finding(
        finding_id=f"{rule_id}-{severity}-{entities}-{privileged}-{effort}",
        rule_id=rule_id,
        platform=Platform.GOOGLE_WORKSPACE,
        check_family=CheckFamily.MFA_COVERAGE,
        title="t",
        severity=severity,
        confidence=confidence,
        affected_entities=affected,
        remediation_key=remediation_key,
        effort_hours=effort,
    )


# -- scoring -------------------------------------------------------------------


def test_severity_drives_the_base_score(matrix):
    ordered = [
        scoring.score(make(severity=s), matrix).total
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    ]
    assert ordered == sorted(ordered, reverse=True)


def test_privileged_entity_raises_the_score(matrix):
    plain = scoring.score(make(entities=1, privileged=0), matrix).total
    admin = scoring.score(make(entities=1, privileged=1), matrix).total
    assert admin > plain
    assert admin == pytest.approx(plain * matrix.modifier("privileged_entity"))


def test_one_privileged_account_is_enough_to_lift_the_finding(matrix):
    """An attacker only needs one, so the modifier is per-finding not per-entity."""
    one = scoring.score(make(entities=10, privileged=1), matrix).total
    many = scoring.score(make(entities=10, privileged=5), matrix).total
    assert one == many


def test_blast_radius_grows_sublinearly(matrix):
    small = scoring.score(make(entities=4), matrix).total
    large = scoring.score(make(entities=40), matrix).total
    assert large > small
    assert large < small * 10, "linear scaling would bury single-account criticals"


def test_blast_radius_is_capped(matrix):
    huge = scoring.blast_radius_modifier(make(entities=100_000), matrix)
    assert huge <= matrix.modifier("blast_radius_cap")


def test_lower_confidence_reduces_the_score(matrix):
    confirmed = scoring.score(make(confidence=Confidence.CONFIRMED), matrix).total
    inferred = scoring.score(make(confidence=Confidence.LOW), matrix).total
    assert inferred < confirmed


def test_a_critical_single_account_outranks_a_medium_tenant_wide_one(matrix):
    """The ordering property the whole matrix exists to produce."""
    critical = scoring.score(make(severity=Severity.CRITICAL, entities=1, privileged=1), matrix)
    medium = scoring.score(make(severity=Severity.MEDIUM, entities=200), matrix)
    assert critical.total > medium.total


def test_explain_returns_the_full_arithmetic(matrix):
    explained = scoring.explain(make(entities=5, privileged=1), matrix)
    product = (
        explained["base"]
        * explained["privilege_modifier"]
        * explained["blast_radius_modifier"]
        * explained["confidence_factor"]
    )
    assert product == pytest.approx(explained["total"], rel=0.01)
    assert "formula" in explained


def test_scoring_does_not_mutate_the_input(matrix):
    original = make()
    scored = scoring.apply([original], matrix)[0]
    assert original.risk_score == 0.0
    assert scored.risk_score > 0


# -- ranking -------------------------------------------------------------------


def test_cheap_fixes_outrank_expensive_ones_at_equal_risk(matrix):
    cheap = scoring.apply([make(effort=0.5, rule_id="cheap")], matrix)[0]
    dear = scoring.apply([make(effort=8.0, rule_id="dear")], matrix)[0]
    ordered = rank([dear, cheap])
    assert ordered[0].finding.rule_id == "cheap"


def test_effort_floor_prevents_an_infinite_ratio():
    assert risk_per_hour(make(effort=0.0)) < float("inf")


def test_ranking_is_deterministic_for_identical_findings(matrix):
    findings = scoring.apply([make(rule_id=f"R-{i}") for i in range(10)], matrix)
    first = [e.finding.finding_id for e in rank(findings)]
    second = [e.finding.finding_id for e in rank(list(reversed(findings)))]
    assert first == second


def test_dedupe_collapses_findings_sharing_a_remediation(matrix):
    """The action plan lists actions, not findings."""
    findings = scoring.apply(
        [make(rule_id=f"R-{i}", remediation_key="oauth.review_broad_scope_apps") for i in range(5)],
        matrix,
    )
    plan = rank(findings, dedupe_by_action=True)
    assert len(plan) == 1
    assert plan[0].covers == 5
    assert len(plan[0].also_resolves) == 4


def test_dedupe_keeps_distinct_actions_separate(matrix):
    findings = scoring.apply(
        [
            make(rule_id="a", remediation_key="mfa.enforce_admins"),
            make(rule_id="b", remediation_key="oauth.review_shadow_it"),
        ],
        matrix,
    )
    assert len(rank(findings, dedupe_by_action=True)) == 2


def test_dedupe_leader_is_the_highest_scoring_member(matrix):
    findings = scoring.apply(
        [
            make(rule_id="low", severity=Severity.LOW, remediation_key="k"),
            make(rule_id="high", severity=Severity.CRITICAL, remediation_key="k"),
        ],
        matrix,
    )
    plan = rank(findings, dedupe_by_action=True)
    assert plan[0].finding.rule_id == "high"


def test_limit_applies_after_deduplication(matrix):
    findings = scoring.apply(
        [make(rule_id=f"R-{i}", remediation_key=f"k{i % 3}") for i in range(12)], matrix
    )
    assert len(rank(findings, limit=10, dedupe_by_action=True)) == 3


# -- posture rating ------------------------------------------------------------


def test_any_critical_means_action_required():
    rating, _ = posture_rating([make(severity=Severity.CRITICAL)])
    assert rating == "Action required"


def test_clean_tenant_reads_as_reasonable():
    rating, _ = posture_rating([make(severity=Severity.LOW)])
    assert rating == "Reasonable"


def test_many_highs_read_as_weak():
    rating, _ = posture_rating([make(severity=Severity.HIGH, rule_id=str(i)) for i in range(6)])
    assert rating == "Weak"


def test_the_seeded_tenant_requires_action(result):
    rating, _ = posture_rating(result.findings)
    assert rating == "Action required"
