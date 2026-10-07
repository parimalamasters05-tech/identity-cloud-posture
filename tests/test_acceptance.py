"""The project brief's weekly done-when tests, as executable assertions.

The brief says: "If a week's done-when test fails, fix it before advancing --
the weeks are dependency-ordered." Checking that by eye invites wishful
thinking, so each criterion that can be verified offline is a test here.

Run just these:  pytest -m acceptance -v

What is NOT here, and why:

  * Week 1 in full. It requires a real dev tenant, a GCP project, and domain-wide
    delegation. See `docs/acceptance-week1.md` for the manual procedure.
  * "A full collection run completes in under five minutes" (week 2). Needs a
    real tenant; the offline path has no network latency to measure. The
    procedure and the timing risk are in the week 1 document.
  * "The top-10 ranking is defensible to a skeptical reader" (week 3). That is a
    human judgement and the brief is right to make it one. What is asserted here
    is the structural property that makes the ranking reviewable at all.
  * "Editorial pass with a non-technical reader" (week 4). Also human, and the
    most valuable hour you will spend on the report.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from tests.conftest import FIXTURE_NOW

from icp.models.enums import CheckFamily, Severity
from icp.normalizers.google import normalize
from icp.reporting.remediation import RemediationLibrary
from icp.risk.ranking import rank
from icp.rules import all_rules, assess

pytestmark = pytest.mark.acceptance

#: Families 1-4, in the brief's order.
WEEK_2_FAMILIES = (
    CheckFamily.MFA_COVERAGE,
    CheckFamily.ADMIN_ROLE_SPRAWL,
    CheckFamily.STALE_ACCOUNTS,
    CheckFamily.SERVICE_ACCOUNT_PRIVILEGE,
)

#: Families 5-7.
WEEK_3_FAMILIES = (
    CheckFamily.EXTERNAL_SHARING,
    CheckFamily.LOGGING_READINESS,
    CheckFamily.OAUTH_GRANTS,
)


# ---------------------------------------------------------------------------
# Week 2 — "the rules engine finds every planted finding for families 1-4
#           with no false positives on the fixture set"
# ---------------------------------------------------------------------------


def test_week2_families_one_to_four_all_produce_findings(result):
    produced = {f.check_family for f in result.findings}
    missing = [str(f) for f in WEEK_2_FAMILIES if f not in produced]
    assert not missing, f"families with no findings: {missing}"


def test_week2_every_planted_finding_for_families_one_to_four_is_detected(findings_by_rule):
    """Each rule below corresponds to a problem deliberately seeded in week 1."""
    expected = {
        "GWS-MFA-001": "super-admin with no second factor",
        "GWS-MFA-002": "staff with no second factor",
        "GWS-MFA-003": "admins without a phishing-resistant factor",
        "GWS-ADM-002": "admin dormant 120 days",
        "GWS-STA-001": "five stale accounts",
        "GWS-STA-002": "accounts never signed into",
        "GWS-STA-003": "suspended accounts retained",
        "GWS-SVC-001": "over-scoped application (admin-equivalent)",
        "GWS-SVC-002": "broad-scope app authorized by an admin",
    }
    missing = {rid: why for rid, why in expected.items() if rid not in findings_by_rule}
    assert not missing, f"planted findings not detected: {missing}"


def test_week2_no_false_positives_on_the_fixture_set(result):
    """The negative case the brief asks for, stated as a property.

    A tool that flags harmless things destroys its own credibility as fast as
    one that misses real ones.

    The check is scoped to the *account-centric* families, and the distinction
    matters. Families 4 and 7 produce findings about an application; the users
    listed are who would be exposed if that application were compromised. A
    healthy administrator who authorized a broad-scope tool belongs in that
    list, and removing them would hide the blast radius, which is the whole
    point of the finding.

    A false positive is that same administrator being flagged for a personal
    failing -- no second factor, dormancy, a never-used account -- when they
    have two security keys and signed in yesterday.
    """
    titles = " ".join(f.title for f in result.findings)
    assert "Payroll Portal" not in titles, "a sign-in-only app was flagged"

    account_centric = (
        CheckFamily.MFA_COVERAGE,
        CheckFamily.ADMIN_ROLE_SPRAWL,
        CheckFamily.STALE_ACCOUNTS,
    )
    personal = [f for f in result.findings if f.check_family in account_centric]
    flagged = {e.label for f in personal for e in f.affected_entities}

    # Two security keys, signed in yesterday.
    assert "dana.reyes@dev-icp.example" not in flagged
    # Second factor enrolled, signed in this week, no admin rights.
    assert "alex.tan@dev-icp.example" not in flagged


def test_week2_a_missing_permission_degrades_one_check_not_the_run(snapshot, matrix):
    """'A missing permission should degrade one check, not crash the run.'"""
    from icp.models.enums import Assessability
    from icp.models.snapshot import CollectionError

    degraded = snapshot.model_copy(
        update={
            "errors": (
                CollectionError(
                    collector="google.oauth_tokens",
                    assessability=Assessability.NOT_ASSESSABLE_PERMISSION,
                    message="Access denied (403).",
                    http_status=403,
                ),
            )
        }
    )
    outcome = assess(normalize(degraded), matrix=matrix, now=FIXTURE_NOW)

    assert outcome.rules_failed == []
    # The other families still report.
    assert any(f.check_family == CheckFamily.MFA_COVERAGE for f in outcome.findings)
    # And the lost family is called out rather than silently absent.
    assert any(
        f.severity == Severity.INFO and f.check_family == CheckFamily.OAUTH_GRANTS for f in outcome.findings
    )


def test_week2_snapshot_records_schema_tenant_timestamp_and_scopes(snapshot):
    """'Snapshot writer with schema version, tenant identifier, timestamp, and
    the exact scope set used.'"""
    assert snapshot.schema_version
    assert snapshot.tenant_id
    assert snapshot.collected_at
    assert hasattr(snapshot, "scopes_used")  # empty on the offline fixture path


# ---------------------------------------------------------------------------
# Week 3 — "all seven families produce findings, the top-10 ranking is
#           defensible, and finding IDs are provably stable across two runs"
# ---------------------------------------------------------------------------


def test_week3_all_seven_families_produce_findings(result):
    produced = {f.check_family for f in result.findings}
    missing = [str(f) for f in CheckFamily if f not in produced]
    assert not missing, f"families with no findings: {missing}"


def test_week3_finding_ids_are_stable_across_two_consecutive_runs(snapshot, matrix):
    """The brief's exact wording: 'provably stable across two consecutive runs'."""
    first = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW)
    second = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW)
    assert {f.finding_id for f in first.findings} == {f.finding_id for f in second.findings}


def test_week3_finding_ids_survive_the_clock_moving(snapshot, matrix):
    """Two runs a week apart on unchanged config must not invent findings.

    Age-threshold rules are excluded: a dormancy finding legitimately gains
    members as time passes, and that is a real change, not churn.
    """
    age_based = {"GWS-STA-001", "GWS-STA-002", "GWS-ADM-002", "GWS-OAU-005"}
    first = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW)
    second = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW + timedelta(days=7))

    ids = lambda r: {f.finding_id for f in r.findings if f.rule_id not in age_based}  # noqa: E731
    assert ids(first) == ids(second)


def test_week3_top_ten_is_ten_distinct_actions(result):
    """The structural property that makes the ranking reviewable.

    Whether the order is *defensible* is your judgement call and the brief is
    right to keep it human. What can be asserted is that the ten rows are ten
    different pieces of work -- if three of them were the same fix stated three
    ways, no reviewer could form a useful opinion about the order.
    """
    actionable = [f for f in result.findings if f.severity != Severity.INFO]
    plan = rank(actionable, limit=10, dedupe_by_action=True)

    assert len(plan) == 10
    keys = [entry.finding.remediation_key for entry in plan]
    assert len(set(keys)) == 10


def test_week3_ranking_is_severity_then_risk_reduced_per_hour(result):
    """Revised after the week-5 top-10 review: see docs/scoring-rubric.md."""
    actionable = [f for f in result.findings if f.severity != Severity.INFO]
    keys = [
        (e.finding.severity.rank, e.risk_per_hour)
        for e in rank(actionable, limit=10, dedupe_by_action=True)
    ]
    assert keys == sorted(keys, reverse=True)


def test_week3_every_finding_can_be_argued_with(result):
    """A ranking is only defensible if its inputs are visible.

    Every finding needs evidence pointing into the snapshot and a documented
    confidence level, or a skeptical reader has nothing to push against.
    """
    for finding in result.findings:
        assert finding.evidence, f"{finding.rule_id} has no evidence"
        assert finding.confidence
        assert finding.risk_score > 0


def test_week3_scope_taxonomy_covers_the_tiers_it_claims(tenant):
    """'Map each Google OAuth scope to a blast-radius tier.'

    Asserts the taxonomy actually discriminates rather than bucketing
    everything into one tier -- which would pass a naive smoke test while
    making the OAuth findings worthless.
    """
    tiers = {s.tier for g in tenant.grants for s in g.scopes}
    assert len(tiers) >= 3, f"taxonomy is not discriminating: {tiers}"


# ---------------------------------------------------------------------------
# Week 4 — the sellable artifact
# ---------------------------------------------------------------------------


def test_week4_remediation_content_exists_for_every_rule(library: RemediationLibrary):
    """'Write the remediation content library -- for all seven families.'"""
    missing = [r.rule_id for r in all_rules() if r.remediation_key not in library.entries]
    assert not missing, f"rules without content: {missing}"


def test_week4_every_remediation_gives_an_admin_console_path(library: RemediationLibrary):
    """'Exact admin-console click paths' -- not 'review your settings'."""
    without_path = [
        key
        for key, entry in library.entries.items()
        if key != "coverage.restore_access"
        and not any(
            marker in step
            for step in entry.steps
            for marker in (
                # Google Workspace
                "Admin console",
                "myaccount.google.com",
                # Microsoft 365 (week 5)
                "Entra admin center",
                "Microsoft 365 admin center",
                "SharePoint admin center",
                "mysignins.microsoft.com",
                "Microsoft Purview portal",
            )
        )
    ]
    assert not without_path, f"remediations with no console path: {without_path}"
