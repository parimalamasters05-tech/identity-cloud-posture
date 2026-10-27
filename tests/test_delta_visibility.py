"""Lost visibility is never reported as remediation (review, 27 Oct 2026).

Reproduced: with Google's OAuth collection refused on the second run, the
delta marked every OAuth and service-account finding resolved, and counted
their risk as removed. A finding is resolved only where its check, and the
accounts it named, were assessed again.
"""

from __future__ import annotations

import pytest
from tests.conftest import FIXTURE_NOW
from tests.test_delta import NOW, make

from icp.delta.compare import compare
from icp.models.enums import Assessability, CheckFamily, Confidence, FindingStatus, Platform, Severity
from icp.models.finding import AffectedEntity, Evidence, Finding
from icp.models.snapshot import CollectionError
from icp.normalizers.google import normalize
from icp.rules import assess

pytestmark = pytest.mark.security

OAUTH_FAMILIES = {CheckFamily.OAUTH_GRANTS, CheckFamily.SERVICE_ACCOUNT_PRIVILEGE}


def _lose_oauth(snapshot):
    refused = CollectionError(
        collector="google.oauth_tokens",
        assessability=Assessability.NOT_ASSESSABLE_PERMISSION,
        message="scope not granted",
    )
    artifacts = {k: v for k, v in snapshot.artifacts.items() if k != "google.oauth_tokens"}
    return snapshot.model_copy(update={"errors": (refused,), "artifacts": artifacts})


def test_losing_the_oauth_permission_resolves_nothing(snapshot, matrix):
    """The review's reproduction."""
    before = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW).findings
    after = assess(normalize(_lose_oauth(snapshot)), matrix=matrix, now=FIXTURE_NOW).findings
    delta = compare(before, after)

    hidden = [f for f in before if f.check_family in OAUTH_FAMILIES and f.severity != Severity.INFO]
    assert len({f.rule_id for f in hidden}) >= 5, "the fixture plants findings across these rules"
    assert delta.resolved == []
    assert {f.finding_id for f in delta.not_revalidated} == {f.finding_id for f in hidden}
    assert all(f.status == FindingStatus.NOT_REVALIDATED for f in delta.not_revalidated)
    # Their risk is not claimed as removed: the total moves by nothing.
    assert delta.risk_totals()["change"] == 0
    assert delta.summary()["not_revalidated"] == len(hidden)


def test_regaining_the_permission_is_first_checked_not_new(snapshot, matrix):
    before = assess(normalize(_lose_oauth(snapshot)), matrix=matrix, now=FIXTURE_NOW).findings
    after = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW).findings
    delta = compare(before, after)
    assert delta.new == []
    assert delta.first_assessed and all(f.check_family in OAUTH_FAMILIES for f in delta.first_assessed)
    assert delta.risk_totals()["change"] == 0


def _coverage(rule_id: str, family: CheckFamily, entities=(), observed=None) -> Finding:
    return Finding(
        finding_id=f"cov-{rule_id}",
        rule_id=rule_id,
        platform=Platform.GOOGLE_WORKSPACE,
        check_family=family,
        title="coverage",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        affected_entities=tuple(entities),
        evidence=(
            Evidence(collector="icp.coverage", pointer="/x", summary="x", observed_values=observed or {}),
        ),
        remediation_key="coverage.restore_access",
        first_seen=NOW,
    )


def test_one_rule_not_assessed_holds_back_only_that_rules_findings():
    gone_unseen, gone_fixed = make("a"), make("b").model_copy(update={"rule_id": "R-2"})
    rule_lost = _coverage(
        "ICP-COVERAGE-002", CheckFamily.MFA_COVERAGE, [AffectedEntity(id="R-1", kind="rule", label="r")]
    )
    delta = compare([gone_unseen, gone_fixed], [rule_lost])
    assert [f.finding_id for f in delta.not_revalidated] == ["a"]
    assert [f.finding_id for f in delta.resolved] == ["b"]
    assert delta.new == []  # the coverage note itself is never a finding


def test_partial_coverage_holds_back_only_findings_naming_unread_accounts():
    names_unread = make("a", entities=2)  # accounts 0 and 1
    names_others = make("b").model_copy(
        update={"affected_entities": (AffectedEntity(id="9", kind="user", label="u9"),)}
    )
    partial = _coverage(
        "ICP-COVERAGE-003",
        CheckFamily.MFA_COVERAGE,
        [AffectedEntity(id="1", kind="user", label="u1")],
        {"families": "mfa_coverage"},
    )
    delta = compare([names_unread, names_others], [partial])
    assert [f.finding_id for f in delta.not_revalidated] == ["a"]
    assert [f.finding_id for f in delta.resolved] == ["b"]


def test_partial_coverage_with_unknown_accounts_holds_back_the_whole_area():
    partial = _coverage(
        "ICP-COVERAGE-003",
        CheckFamily.MFA_COVERAGE,
        [AffectedEntity(id="gap", kind="coverage_gap", label="gap")],
    )
    delta = compare([make("a")], [partial])
    assert delta.resolved == [] and len(delta.not_revalidated) == 1


def test_an_account_gone_from_an_open_finding_but_not_read_is_not_fixed():
    before = make("a", entities=3)  # accounts 0, 1, 2
    after = make("a", entities=2)  # account 2 gone...
    partial = _coverage(
        "ICP-COVERAGE-003", CheckFamily.MFA_COVERAGE, [AffectedEntity(id="2", kind="user", label="u2")]
    )  # ...because it was not read
    delta = compare([before], [after, partial])
    change = delta.changes["a"]
    assert change.removed == () and change.unconfirmed == ("u2",)
    assert delta.improved == [] and len(delta.persisting) == 1


def test_a_fully_reassessed_disappearance_is_still_resolved():
    delta = compare([make("a")], [])
    assert len(delta.resolved) == 1 and delta.not_revalidated == []
