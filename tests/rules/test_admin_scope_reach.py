"""A broad scope is a requested capability, not proof of administrator power.

Review, 27 Oct 2026: GWS-SVC-001 said an app "can act across the whole
organization" from its scopes alone. Admin-console scopes work only through an
administrator's account (which this tool reads); Google Cloud reach depends on
Cloud IAM roles (which it does not).
"""

from __future__ import annotations

from copy import deepcopy

import pytest
from tests.conftest import FIXTURE_NOW

from icp.models.enums import Confidence
from icp.normalizers.google import normalize
from icp.risk.scope_taxonomy import ScopeTaxonomy
from icp.rules import assess

LEGACY = "555666777888.apps.googleusercontent.com"  # the fixture app with admin.directory.user
DANA = "dana.reyes@dev-icp.example"  # a super-administrator in the fixture
ALEX = ("alex.tan@dev-icp.example", "100000000000000000010")  # not an administrator
CLOUD = "https://www.googleapis.com/auth/cloud-platform"


def _finding(snapshot, matrix, **grant):
    artifacts = deepcopy(snapshot.artifacts)
    payload = artifacts["google.oauth_tokens"]
    grants = payload["grants"] if isinstance(payload, dict) else payload
    for g in grants:
        if g["clientId"] == LEGACY:
            g.update(grant)
    tenant = normalize(snapshot.model_copy(update={"artifacts": artifacts}))
    assert any(u.primary_email == DANA and u.is_privileged for u in tenant.users)
    found = [
        f for f in assess(tenant, matrix=matrix, now=FIXTURE_NOW).findings if f.rule_id == "GWS-SVC-001"
    ]
    return next(f for f in found if LEGACY in str(f.evidence[0].observed_values["client_id"]))


def test_granted_by_an_administrator_the_admin_rights_are_confirmed(snapshot, matrix):
    finding = _finding(snapshot, matrix)
    assert "through 1 administrator" in finding.title
    assert "Through that administrator's account" in finding.evidence[0].summary
    assert finding.confidence == Confidence.CONFIRMED
    assert finding.evidence[0].observed_values["admin_rights_confirmed"] is True


def test_granted_by_a_non_administrator_it_is_a_capability_not_a_power(snapshot, matrix):
    confirmed = _finding(snapshot, matrix)
    finding = _finding(snapshot, matrix, userKey=ALEX[0], userId=ALEX[1])
    assert finding.title == "'LegacySync Connector' was given administrator-level permissions"
    summary = finding.evidence[0].summary
    assert "no administrator rights today" in summary and "across the organization" not in summary
    assert finding.confidence == Confidence.HIGH
    assert finding.risk_score < confirmed.risk_score  # still reported, scored as less exposed


def test_google_cloud_reach_is_never_stated_as_confirmed(snapshot, matrix):
    finding = _finding(snapshot, matrix, scopes=[CLOUD], userKey=ALEX[0], userId=ALEX[1])
    summary = finding.evidence[0].summary
    assert "whatever roles those people hold there" in summary
    assert "not confirmed" in summary
    assert finding.evidence[0].observed_values["admin_rights_confirmed"] is False


@pytest.mark.parametrize(
    ("scope", "reach"),
    [
        ("https://www.googleapis.com/auth/admin.directory.user", "workspace_admin"),
        (CLOUD, "cloud_iam"),
        ("https://www.googleapis.com/auth/cloud-identity.groups", "own_groups"),
        ("https://www.googleapis.com/auth/gmail.readonly", ""),
    ],
)
def test_every_administrator_level_scope_says_what_its_reach_depends_on(scope, reach):
    assert ScopeTaxonomy.load_default().reach_for(scope) == reach


def test_no_administrator_level_scope_is_left_without_a_reach():
    from icp.models.enums import ScopeTier

    taxonomy = ScopeTaxonomy.load_default()
    admin = [s for s, r in taxonomy.exact.items() if r["tier"] == ScopeTier.ADMIN_EQUIVALENT]
    assert admin and all(taxonomy.reach_for(s) for s in admin)
