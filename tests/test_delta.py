"""Delta comparison -- the retainer product."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from icp.delta.compare import compare, trend_line
from icp.models.enums import CheckFamily, Confidence, FindingStatus, Platform, Severity
from icp.models.finding import AffectedEntity, Finding

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def make(finding_id: str, *, severity=Severity.HIGH, entities=1, score=25.0, first_seen=NOW) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="R-1",
        platform=Platform.GOOGLE_WORKSPACE,
        check_family=CheckFamily.MFA_COVERAGE,
        title="t",
        severity=severity,
        confidence=Confidence.CONFIRMED,
        affected_entities=tuple(
            AffectedEntity(id=str(i), kind="user", label=f"u{i}") for i in range(entities)
        ),
        remediation_key="mfa.enforce_admins",
        risk_score=score,
        first_seen=first_seen,
    )


def test_resolved_new_and_persisting_are_separated():
    previous = [make("a"), make("b")]
    current = [make("b"), make("c")]
    report = compare(previous, current)

    assert [f.finding_id for f in report.resolved] == ["a"]
    assert [f.finding_id for f in report.new] == ["c"]
    assert [f.finding_id for f in report.persisting] == ["b"]


def test_worsening_severity_is_reported_as_regressed():
    """'This got worse' is a different conversation from 'this is still open'."""
    report = compare([make("a", severity=Severity.MEDIUM)], [make("a", severity=Severity.CRITICAL)])
    assert [f.finding_id for f in report.regressed] == ["a"]
    assert report.persisting == []


def test_growing_entity_count_is_a_regression():
    report = compare([make("a", entities=2)], [make("a", entities=9)])
    assert len(report.regressed) == 1


def test_improving_severity_is_not_a_regression():
    report = compare([make("a", severity=Severity.CRITICAL)], [make("a", severity=Severity.LOW)])
    assert report.regressed == []
    assert len(report.improved) == 1


def test_first_seen_is_carried_forward():
    """'Open since March' is the most persuasive line in a quarterly walkthrough."""
    march = datetime(2026, 3, 1, tzinfo=UTC)
    report = compare([make("a", first_seen=march)], [make("a", first_seen=NOW)])
    assert report.persisting[0].first_seen == march


def test_statuses_are_set_on_every_bucket():
    report = compare([make("a")], [make("b")])
    assert report.resolved[0].status == FindingStatus.RESOLVED
    assert report.new[0].status == FindingStatus.NEW


def test_risk_totals_show_direction_of_travel():
    report = compare([make("a", score=40.0), make("b", score=10.0)], [make("b", score=10.0)])
    totals = report.risk_totals()
    assert totals["previous"] == 50.0
    assert totals["current"] == 10.0
    assert totals["change"] == -40.0


def test_summary_counts_resolved_critical_and_high():
    previous = [make("a", severity=Severity.CRITICAL), make("b", severity=Severity.LOW)]
    report = compare(previous, [])
    assert report.summary()["resolved_critical_high"] == 1


def test_identical_assessments_show_no_change():
    findings = [make("a"), make("b")]
    report = compare(findings, findings)
    assert report.net_change == 0
    assert report.new == []
    assert report.resolved == []


def test_trend_line_orders_by_date_and_ignores_coverage_notes():
    history = [
        (NOW, [make("a"), make("b", severity=Severity.INFO)]),
        (NOW - timedelta(days=90), [make("a"), make("c")]),
    ]
    points = trend_line(history)
    assert len(points) == 2
    assert points[0]["at"] < points[1]["at"]
    assert points[1]["total_findings"] == 1  # the INFO note is excluded
