"""Rules against the frozen, pseudonymized copy of the real dev tenant.

The synthetic set (`fixtures/google`) proves every planted problem is caught.
This set proves the rules read what Google actually returns: real field shapes,
real first-party client IDs, a real passkey. Every assertion below is a fact
about that tenant when it was frozen, checked by hand.

Frozen from snapshot 20260929T063729908Z (29 Sep 2026, 06:37 UTC), after the
day's live tests: two admins demoted to delegated roles and enrolled in 2SV,
Hunter and the OAuth Playground grants revoked, the security-key report fix.

After `icp freeze-fixtures` these expectations must be reviewed and updated:
a failure then means "the tenant changed", which is the point of pinning it.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from tests.conftest import REPO_ROOT, entity_labels

from icp.collectors.google import load_fixture_snapshot
from icp.normalizers.google import normalize
from icp.rules import assess

DEV_DIR = REPO_ROOT / "fixtures" / "google-dev"

pytestmark = pytest.mark.skipif(not DEV_DIR.exists(), reason="no frozen dev-tenant fixture set")


def at(local: str) -> str:
    return f"{local}@tenant.example"


@pytest.fixture(scope="module")
def dev_snapshot():
    return load_fixture_snapshot(Path(DEV_DIR), tenant_id="dev")


@pytest.fixture(scope="module")
def dev_tenant(dev_snapshot):
    return normalize(dev_snapshot)


@pytest.fixture(scope="module")
def dev_result(dev_snapshot, dev_tenant, matrix):
    # Pinned to the moment of collection: "created a week ago" must stay a week.
    return assess(dev_tenant, matrix=matrix, now=dev_snapshot.collected_at)


@pytest.fixture(scope="module")
def dev_by_rule(dev_result) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for finding in dev_result.findings:
        grouped.setdefault(finding.rule_id, []).append(finding)
    return grouped


def test_the_run_facts_survive_the_freeze(dev_snapshot, dev_tenant):
    assert dev_snapshot.collected_at == datetime.fromisoformat("2026-09-29T06:37:29.908944+00:00")
    # The security-key report works now: nothing degraded.
    assert dev_snapshot.degraded_collectors() == ()
    # Drive could not be searched for the two suspended accounts.
    assert list(dev_snapshot.partial) == ["google.public_drive_items"]
    # The profile name is the domain; both freeze to the same alias.
    assert dev_tenant.organization_name == dev_tenant.primary_domain == "tenant.example"


def test_nothing_identifying_is_in_the_frozen_set():
    import re

    for path in DEV_DIR.glob("*.json"):
        for address in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", path.read_text("utf-8")):
            assert address.endswith("@tenant.example"), f"{path.name} holds a real address"


# -- families 1-4, exactly -----------------------------------------------------

EXPECTED = {
    # the super-admin and the service account that never enrolled
    "GWS-MFA-001": {at("admin02"), at("user01")},
    # active non-admins without 2SV; the two suspended accounts are excluded
    "GWS-MFA-002": {at("user02"), at("user04"), at("user06"), at("user07")},
    # the two delegated admins enrolled with a phone prompt or code; admin01
    # has a passkey and is correctly absent
    "GWS-MFA-003": {at("user08"), at("user09")},
    "GWS-STA-003": {at("user03"), at("user05")},
}


@pytest.mark.parametrize("rule_id", sorted(EXPECTED))
def test_names_exactly_the_right_accounts(dev_by_rule, rule_id):
    findings = dev_by_rule.get(rule_id, [])
    assert len(findings) == 1
    assert entity_labels(findings[0]) == EXPECTED[rule_id]


def test_a_real_passkey_counts_as_phishing_resistant(dev_tenant):
    """First live proof: Google reports passkeys separately from security keys,
    and an admin with only a passkey is not flagged by MFA-003."""
    admin = next(u for u in dev_tenant.users if u.label == at("admin01"))
    assert [m.method for m in admin.mfa_methods] == ["passkey"]
    assert admin.has_phishing_resistant_mfa


def test_two_super_admins_is_within_the_small_org_minimum(dev_by_rule):
    """ADM-001 fired at 3 super-admins; after demoting one, 2 is the floor."""
    assert "GWS-ADM-001" not in dev_by_rule


@pytest.mark.parametrize("rule_id", ["GWS-ADM-002", "GWS-STA-001", "GWS-STA-002"])
def test_age_based_checks_do_not_fire_on_a_week_old_tenant(dev_by_rule, rule_id):
    """Accounts were created about a week before collection. "Never signed in"
    and "dormant" need an account older than the window."""
    assert rule_id not in dev_by_rule


def test_gcloud_and_adc_logins_are_one_developer_tool_finding(dev_by_rule):
    findings = dev_by_rule["GWS-SVC-003"]
    assert len(findings) == 1
    assert entity_labels(findings[0]) == {at("admin01")}


def test_sign_in_only_and_device_grants_are_never_flagged(dev_result):
    """Composio (sign-in only), Chrome and Android sign-in, and the Playground
    grant that remains with names-and-listings access only."""
    for finding in dev_result.findings:
        for name in ("Composio", "Google Chrome", "Android device", "Playground"):
            assert name not in finding.title, f"{finding.rule_id} flagged {name}"


# -- family 7: OAuth grants ------------------------------------------------------


def test_only_apollo_remains_a_broad_third_party_app(dev_by_rule):
    """Hunter and the Playground's broad grants were revoked in the live tests."""
    for rule_id in ("GWS-OAU-002", "GWS-OAU-004", "GWS-SVC-002"):
        [finding] = dev_by_rule[rule_id]
        assert "Apollo" in finding.title
        assert entity_labels(finding) == {at("admin01")}


def test_no_admin_equivalent_departed_or_unregistered_app_findings(dev_by_rule):
    assert "GWS-SVC-001" not in dev_by_rule
    assert "GWS-OAU-001" not in dev_by_rule
    assert "GWS-OAU-003" not in dev_by_rule


def test_consent_only_token_log_makes_dormancy_not_assessed(dev_result, dev_by_rule):
    assert "GWS-OAU-005" not in dev_by_rule
    assert "not when they were used" in dev_result.unassessable["GWS-OAU-005"]


def test_inventory_lists_every_app_with_its_kind(dev_tenant):
    apps = {a.name: a for a in dev_tenant.applications}
    assert set(apps) == {
        "Apollo",
        "Composio",
        "Google OAuth 2.0 Playground",
        "Google Chrome",
        "Android device",
        "Google Cloud SDK",
        "Google Auth Library",
    }
    assert apps["Google Chrome"].first_party_kind == "device_sign_in"
    assert apps["Android device"].first_party_kind == "device_sign_in"
    assert apps["Google Cloud SDK"].first_party_kind == "developer_tool"
    assert apps["Apollo"].first_party_kind is None


# -- family 5: sharing -----------------------------------------------------------


def test_public_files_found_across_owners(dev_by_rule):
    assert entity_labels(dev_by_rule["GWS-SHR-001"][0]) == {"Public item 01", "Public item 02"}
    # The warning is on again for every department.
    assert "GWS-SHR-002" not in dev_by_rule


def test_suspended_owners_are_named_as_not_searched(dev_result):
    note = next(f for f in dev_result.findings if f.rule_id == "ICP-COVERAGE-003")
    reason = note.evidence[0].summary
    assert at("user03") in reason and at("user05") in reason
