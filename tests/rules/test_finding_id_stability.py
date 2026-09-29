"""Finding IDs must be stable forever.

The delta report -- which is the retainer product -- is a diff keyed on finding
ID. If an ID moves when a finding's score or wording changes, every quarterly
report shows churn that did not happen, and the trend line becomes noise.

Cheap to guarantee now, very expensive to retrofit once clients hold historical
reports.
"""

from __future__ import annotations

from datetime import timedelta

from tests.conftest import FIXTURE_NOW

from icp.models.enums import CheckFamily, Confidence, Platform, Severity
from icp.models.finding import AffectedEntity, Finding, build_finding_id
from icp.normalizers.google import normalize
from icp.rules import assess


def entity(identifier: str, *, label: str = "x", privileged: bool = False) -> AffectedEntity:
    return AffectedEntity(id=identifier, kind="user", label=label, is_privileged=privileged)


def build(**overrides) -> str:
    params = {
        "platform": Platform.GOOGLE_WORKSPACE,
        "rule_id": "GWS-MFA-001",
        "discriminator": "",
    }
    params.update(overrides)
    return build_finding_id(**params)


def test_identical_inputs_produce_identical_ids():
    assert build() == build()


def test_affected_accounts_are_not_an_input():
    """The v1 bug: the ID hashed who was affected, so fixing one of eight
    accounts "resolved" the finding and opened a new one."""
    import inspect

    assert "entities" not in inspect.signature(build_finding_id).parameters


def test_different_rules_produce_different_ids():
    assert build(rule_id="GWS-MFA-001") != build(rule_id="GWS-MFA-002")


def test_discriminator_separates_per_application_findings():
    """One rule legitimately emits one finding per OAuth application."""
    assert build(discriminator="app-a") != build(discriminator="app-b")


def test_different_platforms_produce_different_ids():
    a = build(platform=Platform.GOOGLE_WORKSPACE)
    b = build(platform=Platform.MICROSOFT_365)
    assert a != b


def test_score_and_severity_are_not_inputs_to_the_id():
    """The regression this guards against is subtle and expensive.

    If severity fed the hash, a finding whose severity rose from high to
    critical would appear in the delta as one resolved and one new finding --
    exactly inverting the message the client should receive.
    """
    common = {
        "finding_id": "placeholder",
        "rule_id": "GWS-MFA-001",
        "platform": Platform.GOOGLE_WORKSPACE,
        "check_family": CheckFamily.MFA_COVERAGE,
        "title": "t",
        "confidence": Confidence.CONFIRMED,
        "affected_entities": (entity("1"),),
        "remediation_key": "mfa.enforce_admins",
    }
    low = Finding(**common, severity=Severity.LOW, risk_score=1.0)
    high = Finding(**common, severity=Severity.CRITICAL, risk_score=99.0)

    recompute = lambda f: build_finding_id(platform=f.platform, rule_id=f.rule_id)  # noqa: E731
    assert recompute(low) == recompute(high)


# -- the quarterly diff, end to end --------------------------------------------


def _with_users(snapshot, change):
    users = [change(u) for u in snapshot.artifacts["google.users"]]
    return snapshot.model_copy(update={"artifacts": {**snapshot.artifacts, "google.users": users}})


def test_fixing_one_account_is_an_improvement_not_a_new_finding(snapshot, matrix):
    from icp.delta.compare import compare

    enrolled = _with_users(
        snapshot,
        lambda u: {**u, "isEnrolledIn2Sv": True} if u["primaryEmail"].startswith("pat.dunne") else u,
    )
    q1 = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW).findings
    q2 = assess(normalize(enrolled), matrix=matrix, now=FIXTURE_NOW).findings
    delta = compare(q1, q2)

    assert delta.new == [] and delta.resolved == []
    [improved] = delta.improved
    assert improved.rule_id == "GWS-MFA-002"
    change = delta.changes[improved.finding_id]
    assert change.removed == ("pat.dunne@dev-icp.example",)
    assert (change.previous_count, change.current_count) == (8, 7)


def test_a_new_account_joining_a_finding_is_a_regression_not_a_new_finding(snapshot, matrix):
    from icp.delta.compare import compare

    lapsed = _with_users(
        snapshot,
        lambda u: {**u, "isEnrolledIn2Sv": False} if u["primaryEmail"].startswith("alex.tan") else u,
    )
    q1 = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW).findings
    q2 = assess(normalize(lapsed), matrix=matrix, now=FIXTURE_NOW).findings
    delta = compare(q1, q2)

    assert delta.new == [] and delta.resolved == []
    [regressed] = delta.regressed
    assert delta.changes[regressed.finding_id].added == ("alex.tan@dev-icp.example",)


def test_fixing_every_account_resolves_the_finding(snapshot, matrix):
    from icp.delta.compare import compare

    fixed = _with_users(snapshot, lambda u: {**u, "isEnrolledIn2Sv": True})
    q1 = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW).findings
    q2 = assess(normalize(fixed), matrix=matrix, now=FIXTURE_NOW).findings
    resolved = {f.rule_id for f in compare(q1, q2).resolved}
    assert {"GWS-MFA-001", "GWS-MFA-002"} <= resolved


def test_per_application_findings_keep_their_own_ids(snapshot, matrix):
    """One OAU-002 finding per app: a user leaving NoteTaker must not move it,
    and NoteTaker's ID must differ from LegacySync's."""
    result = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW)
    per_app = [f for f in result.findings if f.rule_id == "GWS-OAU-002"]
    assert len({f.finding_id for f in per_app}) == len(per_app) > 1


def test_ids_are_stable_across_two_full_assessment_runs(snapshot, matrix):
    """End-to-end, not just the hash function."""
    first = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW)
    second = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW)
    assert {f.finding_id for f in first.findings} == {f.finding_id for f in second.findings}


def test_ids_are_stable_when_the_clock_moves(snapshot, matrix):
    """A re-run tomorrow must not invent new findings out of unchanged config.

    Under v1 the age-threshold rules had to be excluded here: a dormancy
    finding gaining a member as time passed got a new ID. Now nothing is.
    """
    later = FIXTURE_NOW + timedelta(days=3)
    first = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW)
    second = assess(normalize(snapshot), matrix=matrix, now=later)

    assert {f.finding_id for f in first.findings} == {f.finding_id for f in second.findings}


def test_ids_are_unique_within_one_assessment(result):
    ids = [f.finding_id for f in result.findings]
    assert len(ids) == len(set(ids)), "two findings share an ID; the delta would merge them"


def test_id_is_short_enough_to_print_and_long_enough_to_be_unique(result):
    for finding in result.findings:
        assert len(finding.finding_id) == 16
        assert finding.finding_id.isalnum()
