"""The most important test in the suite.

The dev tenant was seeded with known problems (see `tools/generate_fixtures.py`).
Every one of them must be detected, and nothing benign may be flagged. This is
the test that stops a refactor from silently turning a paid deliverable into a
document that misses the thing the client was paying to find out.

False negatives and false positives are asserted with equal force. A tool that
flags a harmless sign-in-only app destroys its own credibility just as fast as
one that misses a live exfiltration path.
"""

from __future__ import annotations

import pytest
from tests.conftest import entity_labels

from icp.models.enums import CheckFamily, Severity

DOMAIN = "dev-icp.example"


def email(local: str) -> str:
    return f"{local}@{DOMAIN}"


# -- every planted finding is detected ----------------------------------------


def test_every_rule_ran_without_error(result):
    from icp.rules import all_rules

    assert result.rules_failed == [], f"rules raised: {result.rules_failed}"
    # Every rule either ran or produced an explicit coverage note; none vanished.
    # Counted per platform: a Google tenant runs the Google rules only.
    from icp.models.enums import Platform

    google_rules = [r for r in all_rules() if Platform.GOOGLE_WORKSPACE in r.platforms]
    not_assessed = [k for k in result.unassessable if k.startswith("GWS-")]
    assert result.rules_run + len(not_assessed) == len(google_rules) == 20


def test_sharing_warning_finding_names_only_the_unwarned_unit(findings_by_rule):
    """Planted: the top-level unit shares externally with no warning; the
    finance unit disallows external sharing and must not be blamed."""
    finding = findings_by_rule["GWS-SHR-002"][0]
    units = {ev.observed_values.get("org_unit") for ev in finding.evidence}
    assert units == {"orgUnits/fixture-root"}


def test_unknown_sharing_policy_is_a_coverage_note_not_a_finding(snapshot, matrix):
    """A snapshot without the policy artifact -- any snapshot taken before this
    collector existed. GWS-SHR-002 used to fire anyway, from default values,
    with evidence claiming an observation that was never made."""
    from tests.conftest import FIXTURE_NOW

    from icp.normalizers.google import normalize
    from icp.rules import assess

    artifacts = {k: v for k, v in snapshot.artifacts.items() if k != "google.workspace_policies"}
    result = assess(
        normalize(snapshot.model_copy(update={"artifacts": artifacts})), matrix=matrix, now=FIXTURE_NOW
    )

    assert not any(f.rule_id == "GWS-SHR-002" for f in result.findings)
    assert "GWS-SHR-002" in result.unassessable


@pytest.mark.parametrize(
    "rule_id",
    [
        "GWS-MFA-001",  # admin with no 2SV
        "GWS-MFA-002",  # staff with no 2SV
        "GWS-MFA-003",  # admins without phishing-resistant factors
        "GWS-ADM-002",  # dormant admin
        "GWS-STA-001",  # dormant accounts
        "GWS-STA-002",  # never signed in
        "GWS-STA-003",  # suspended retained
        "GWS-SVC-001",  # admin-equivalent app
        "GWS-SVC-002",  # admin-authorized broad app
        "GWS-SVC-003",  # admin signed in to Google Cloud SDK
        "GWS-SHR-001",  # public Drive items
        "GWS-SHR-002",  # sharing without warnings (from the Workspace policy)
        "GWS-LOG-001",  # unavailable sign-in audit stream
        "GWS-OAU-001",  # grants held by departed staff
        "GWS-OAU-002",  # broad-scope applications
        "GWS-OAU-003",  # unverified application
        "GWS-OAU-004",  # single-user broad-scope app
        "GWS-OAU-005",  # broad app unused for 150 days
    ],
)
def test_planted_finding_detected(findings_by_rule, rule_id):
    assert rule_id in findings_by_rule, f"{rule_id} did not fire against the seeded fixture"


#: Families 1-4, exactly. "It fired" would pass with a healthy account wrongly
#: included; each rule must name the planted accounts and nothing else.
PLANTED_EXACT = {
    "GWS-MFA-001": {"sam.okafor"},
    "GWS-MFA-002": {
        # the six planted, plus the two never-used accounts created without 2SV;
        # sam.okafor is an admin and reported once, under MFA-001
        "pat.dunne",
        "quinn.reilly",
        "rosa.mendes",
        "sean.byrne",
        "tara.singh",
        "umar.khan",
        "new.starter.a",
        "project.placeholder",
    },
    # dana.reyes has security keys; sam.okafor has no second factor at all (MFA-001)
    "GWS-MFA-003": {"former.consultant", "priya.menon"},
    "GWS-ADM-002": {"former.consultant"},
    # the five planted, plus the dormant super-admin; suspended accounts are STA-003's
    "GWS-STA-001": {"vic.nowak", "wes.olsen", "xena.abara", "yuri.baros", "zoe.carr", "former.consultant"},
    "GWS-STA-002": {"new.starter.a", "project.placeholder"},
    "GWS-STA-003": {"departed.finance", "departed.ops"},
    "GWS-SVC-001": {"dana.reyes"},
    "GWS-SVC-002": {"dana.reyes"},
    "GWS-SVC-003": {"priya.menon"},
}


@pytest.mark.parametrize("rule_id", sorted(PLANTED_EXACT))
def test_families_1_to_4_name_exactly_the_planted_accounts(findings_by_rule, rule_id):
    findings = findings_by_rule.get(rule_id, [])
    assert len(findings) == 1, f"{rule_id}: expected one finding, got {[f.title for f in findings]}"
    assert entity_labels(findings[0]) == {email(u) for u in PLANTED_EXACT[rule_id]}


def test_service_account_findings_name_only_the_planted_apps(findings_by_rule):
    assert "LegacySync Connector" in findings_by_rule["GWS-SVC-002"][0].title
    assert "Google Cloud SDK" in findings_by_rule["GWS-SVC-003"][0].title


def test_gcloud_login_is_never_a_third_party_app_finding(result):
    """First-party by client ID: reported once, as a developer-tool login."""
    third_party_rules = {"GWS-SVC-001", "GWS-SVC-002", "GWS-OAU-002", "GWS-OAU-003", "GWS-OAU-004"}
    assert not any("Google Cloud SDK" in f.title for f in result.findings if f.rule_id in third_party_rules)


NOTETAKER_USERS = {
    "alex.tan",
    "bea.novak",
    "chris.dube",
    "dee.ali",
    "eli.park",
    "fran.mbeki",
    "gus.iversen",
    "hana.sato",
    "ivan.petrov",
    "jo.kelly",
    "kim.larsen",
    "leo.costa",
    "departed.finance",
}
ANON = "999000111222"

#: Family 7, per application: (name in the title) -> exactly who is named.
OAUTH_EXACT = {
    "GWS-OAU-001": {"": {"departed.finance", "departed.ops"}},
    "GWS-OAU-002": {
        "NoteTaker AI": NOTETAKER_USERS,
        "LegacySync Connector": {"dana.reyes"},
        "InboxCleaner Pro": {"kim.larsen"},
        "ExpenseTracker": {"departed.ops"},
        ANON: {"ivan.petrov"},
    },
    "GWS-OAU-003": {ANON: {"ivan.petrov"}},
    "GWS-OAU-004": {
        "LegacySync Connector": {"dana.reyes"},
        "InboxCleaner Pro": {"kim.larsen"},
        "ExpenseTracker": {"departed.ops"},
        ANON: {"ivan.petrov"},
    },
    # Only the app unused for 150 days. NoteTaker is in daily use; Payroll
    # Portal is sign-in only; ExpenseTracker's holder is suspended (OAU-001).
    "GWS-OAU-005": {"": {"kim.larsen"}},
}


@pytest.mark.parametrize("rule_id", sorted(OAUTH_EXACT))
def test_oauth_rules_name_exactly_the_planted_apps_and_users(findings_by_rule, rule_id):
    expected = OAUTH_EXACT[rule_id]
    findings = findings_by_rule.get(rule_id, [])
    assert len(findings) == len(expected), [f.title for f in findings]
    for app, users in expected.items():
        matching = [f for f in findings if app in f.title]
        assert len(matching) == 1, f"{rule_id}: {app!r} in {[f.title for f in findings]}"
        assert entity_labels(matching[0]) == {email(u) for u in users}


def test_dormant_app_evidence_names_the_app_and_last_use(findings_by_rule):
    evidence = findings_by_rule["GWS-OAU-005"][0].evidence
    assert len(evidence) == 1
    assert "InboxCleaner Pro" in evidence[0].summary
    assert "last used 2026-04-04" in evidence[0].summary


def test_one_more_super_admin_crosses_the_ceiling(snapshot, matrix):
    """The positive case for GWS-ADM-001. 3 of 32 is under 10%; 4 of 32 is not."""
    from tests.conftest import FIXTURE_NOW

    from icp.normalizers.google import normalize
    from icp.rules import assess

    promoted = email("alex.tan")
    users = [
        {**u, "isAdmin": True} if u["primaryEmail"] == promoted else u
        for u in snapshot.artifacts["google.users"]
    ]
    artifacts = {**snapshot.artifacts, "google.users": users}
    result = assess(
        normalize(snapshot.model_copy(update={"artifacts": artifacts})), matrix=matrix, now=FIXTURE_NOW
    )

    findings = [f for f in result.findings if f.rule_id == "GWS-ADM-001"]
    assert len(findings) == 1
    assert entity_labels(findings[0]) == {
        email("dana.reyes"),
        email("sam.okafor"),
        email("former.consultant"),
        promoted,
    }


def test_admin_without_mfa_names_the_right_account(findings_by_rule):
    finding = findings_by_rule["GWS-MFA-001"][0]
    assert entity_labels(finding) == {email("sam.okafor")}
    assert finding.severity == Severity.CRITICAL
    assert finding.privileged_entity_count == 1


def test_dormant_admin_is_the_former_consultant(findings_by_rule):
    finding = findings_by_rule["GWS-ADM-002"][0]
    assert entity_labels(finding) == {email("former.consultant")}


def test_departed_staff_grants_name_both_suspended_users(findings_by_rule):
    finding = findings_by_rule["GWS-OAU-001"][0]
    assert entity_labels(finding) == {email("departed.finance"), email("departed.ops")}
    assert finding.severity == Severity.CRITICAL


def test_admin_equivalent_app_is_legacysync(findings_by_rule):
    titles = [f.title for f in findings_by_rule["GWS-SVC-001"]]
    assert any("LegacySync Connector" in t for t in titles)


def test_broad_scope_app_covers_thirteen_users(findings_by_rule):
    notetaker = [f for f in findings_by_rule["GWS-OAU-002"] if "NoteTaker AI" in f.title]
    assert len(notetaker) == 1
    # Twelve active staff plus one suspended account that still holds the grant.
    assert notetaker[0].entity_count == 13


def test_public_drive_items_include_the_donor_list(findings_by_rule):
    finding = findings_by_rule["GWS-SHR-001"][0]
    assert "Donor List - master" in entity_labels(finding)
    assert finding.entity_count == 3


def test_never_used_accounts_detected(findings_by_rule):
    finding = findings_by_rule["GWS-STA-002"][0]
    assert entity_labels(finding) == {email("new.starter.a"), email("project.placeholder")}


def test_missing_audit_stream_is_the_sign_in_log(findings_by_rule):
    finding = findings_by_rule["GWS-LOG-001"][0]
    assert entity_labels(finding) == {"login activity log"}


# -- nothing benign is flagged -------------------------------------------------


def test_sign_in_only_app_is_never_flagged(result):
    """`Payroll Portal` holds openid + email across 20 users.

    It is the single most important negative case in the fixture set. If a
    sign-in-only application ever appears in the OAuth findings, the scope
    taxonomy has regressed and every report becomes noise.
    """
    oauth = [f for f in result.findings if f.check_family == CheckFamily.OAUTH_GRANTS]
    assert not any("Payroll Portal" in f.title for f in oauth)

    service = [f for f in result.findings if f.check_family == CheckFamily.SERVICE_ACCOUNT_PRIVILEGE]
    assert not any("Payroll Portal" in f.title for f in service)


def test_healthy_admin_is_not_flagged_for_mfa(findings_by_rule):
    """dana.reyes has two security keys and signed in yesterday."""
    flagged = set()
    for rule_id in ("GWS-MFA-001", "GWS-MFA-003", "GWS-ADM-002"):
        for finding in findings_by_rule.get(rule_id, []):
            flagged |= entity_labels(finding)
    assert email("dana.reyes") not in flagged


def test_recently_active_staff_not_reported_as_dormant(findings_by_rule):
    dormant = entity_labels(findings_by_rule["GWS-STA-001"][0])
    assert email("alex.tan") not in dormant
    assert email("bea.novak") not in dormant


def test_super_admin_count_within_ceiling_does_not_fire(findings_by_rule):
    """Three super-admins out of 32 staff is under both thresholds.

    Asserting the *absence* of GWS-ADM-001 here is deliberate: it proves the
    rule is threshold-driven rather than firing on any tenant with admins.
    """
    assert "GWS-ADM-001" not in findings_by_rule


def test_new_accounts_are_not_reported_as_never_used(tenant, result):
    """The age floor on GWS-STA-002 exists so onboarding does not create noise."""
    never_used = next(f for f in result.findings if f.rule_id == "GWS-STA-002")
    assert never_used.entity_count == 2
