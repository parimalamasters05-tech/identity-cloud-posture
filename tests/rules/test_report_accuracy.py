"""Statements in the report that were false against a real tenant.

Each test here pins a sentence a client would have caught: a claim that did
not match their own admin console.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from tests.conftest import FIXTURE_NOW

from icp.models.enums import IdentityKind, Platform
from icp.models.identity import Identity
from icp.models.snapshot import Snapshot
from icp.normalizers.base import NormalizedTenant
from icp.normalizers.google import normalize
from icp.rules import assess
from icp.rules.admin_role_sprawl import DormantAdministrators
from icp.rules.base import RuleContext


def _tenant(*identities: Identity) -> NormalizedTenant:
    snapshot = Snapshot(snapshot_id="s", tenant_id="t", platform="google_workspace", artifacts={})
    return NormalizedTenant(
        platform=Platform.GOOGLE_WORKSPACE, tenant_id="t", snapshot=snapshot, identities=list(identities)
    )


def _admin(local: str, *, created_days_ago: int, last_login_days_ago: int | None) -> Identity:
    return Identity(
        id=local,
        platform=Platform.GOOGLE_WORKSPACE,
        kind=IdentityKind.USER,
        primary_email=f"{local}@lab.example",
        is_admin=True,
        is_super_admin=True,
        created_at=FIXTURE_NOW - timedelta(days=created_days_ago),
        last_login_at=(
            None if last_login_days_ago is None else FIXTURE_NOW - timedelta(days=last_login_days_ago)
        ),
    )


GCLOUD_SDK = "32555940559.apps.googleusercontent.com"
GCLOUD_ADC = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform"


def _grants_tenant(*grants: tuple[str, str]) -> NormalizedTenant:
    """One active super-admin holding the given (client_id, display name) grants."""
    snapshot = Snapshot(
        snapshot_id="s",
        tenant_id="t",
        platform="google_workspace",
        artifacts={
            "google.users": [
                {
                    "id": "1",
                    "primaryEmail": "admin@lab.example",
                    "isAdmin": True,
                    "isEnrolledIn2Sv": True,
                    "creationTime": "2025-01-01T00:00:00Z",
                    "lastLoginTime": "2026-09-01T00:00:00Z",
                }
            ],
            "google.oauth_tokens": {
                "grants": [
                    {
                        "clientId": client_id,
                        "displayText": name,
                        "scopes": [CLOUD_PLATFORM],
                        "userKey": "admin@lab.example",
                        "userId": "1",
                    }
                    for client_id, name in grants
                ]
            },
        },
    )
    return normalize(snapshot)


def test_google_own_tools_are_not_reported_as_third_party_apps(matrix):
    """Against a real tenant: the assessor's own gcloud login was the #2 and #3
    headline risk, as a "third-party application", four findings each."""
    tenant = _grants_tenant((GCLOUD_SDK, "Google Cloud SDK"), (GCLOUD_ADC, "Google Auth Library"))
    result = assess(tenant, matrix=matrix, now=FIXTURE_NOW)
    fired = {f.rule_id for f in result.findings}

    assert fired.isdisjoint({"GWS-SVC-001", "GWS-SVC-002", "GWS-OAU-002", "GWS-OAU-004", "GWS-OAU-005"})
    dev_tools = [f for f in result.findings if f.rule_id == "GWS-SVC-003"]
    assert len(dev_tools) == 1, "the login is still a live credential and must be reported once"
    assert "Google Cloud SDK" in dev_tools[0].title


@pytest.mark.security
def test_an_app_calling_itself_google_cloud_sdk_is_still_third_party(matrix):
    """First-party status is by client ID only. A display name is attacker-chosen."""
    tenant = _grants_tenant(("999-impostor.apps.googleusercontent.com", "Google Cloud SDK"))
    result = assess(tenant, matrix=matrix, now=FIXTURE_NOW)
    fired = {f.rule_id for f in result.findings}

    assert "GWS-SVC-001" in fired
    assert "GWS-SVC-003" not in fired


@pytest.mark.parametrize(
    "allowed,warning,fires",
    [(True, False, True), (True, True, False), (False, False, False)],
)
def test_sharing_warning_rule_reads_the_policy_it_reports(matrix, allowed, warning, fires):
    """When the policy is known, the finding must follow it -- both ways."""
    from icp.models.resource import DomainPolicy
    from icp.rules.external_sharing import OrgWideSharingUnrestricted

    tenant = _tenant()
    tenant.policy = DomainPolicy(
        platform=Platform.GOOGLE_WORKSPACE,
        domain="lab.example",
        external_sharing_allowed=allowed,
        external_sharing_warning_enabled=warning,
    )
    findings = OrgWideSharingUnrestricted().evaluate(tenant, RuleContext(matrix=matrix, now=FIXTURE_NOW))
    assert bool(findings) is fires


def test_sharing_warning_rule_refuses_to_guess(matrix):
    """Found against a real tenant: this finding appeared with nothing collected."""
    from icp.models.resource import DomainPolicy
    from icp.rules.base import RuleNotAssessable
    from icp.rules.external_sharing import OrgWideSharingUnrestricted

    tenant = _tenant()
    tenant.policy = DomainPolicy(platform=Platform.GOOGLE_WORKSPACE, domain="lab.example")
    with pytest.raises(RuleNotAssessable):
        OrgWideSharingUnrestricted().evaluate(tenant, RuleContext(matrix=matrix, now=FIXTURE_NOW))


def test_new_admin_that_never_signed_in_is_not_called_unused_for_45_days(matrix):
    """Against a real tenant: admins created days earlier were reported as
    "unused for 45+ days" because "never signed in" was read as "dormant"."""
    tenant = _tenant(
        _admin("brand.new", created_days_ago=3, last_login_days_ago=None),
        _admin("old.unclaimed", created_days_ago=200, last_login_days_ago=None),
        _admin("old.lapsed", created_days_ago=400, last_login_days_ago=120),
        _admin("active", created_days_ago=400, last_login_days_ago=1),
    )
    findings = DormantAdministrators().evaluate(tenant, RuleContext(matrix=matrix, now=FIXTURE_NOW))

    assert len(findings) == 1
    flagged = {e.id for e in findings[0].affected_entities}
    assert flagged == {"old.unclaimed", "old.lapsed"}
    assert any("created on" in ev.summary for ev in findings[0].evidence)
