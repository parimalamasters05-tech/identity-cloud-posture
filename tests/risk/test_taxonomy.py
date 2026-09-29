"""The scope taxonomy: complete for what we have seen, and never under-rated.

The brief calls this file the project's intellectual property. These tests are
what stop it from quietly rotting: a scope seen in a real tenant must be
classified, and a known-dangerous scope must never drift to a lower tier.
"""

from __future__ import annotations

import json

import pytest
from tests.conftest import REPO_ROOT

from icp.models.enums import ScopeTier
from icp.risk.scope_taxonomy import ScopeTaxonomy

G = "https://www.googleapis.com/auth/"


@pytest.fixture(scope="module")
def taxonomy() -> ScopeTaxonomy:
    return ScopeTaxonomy.load_default(REPO_ROOT / "config")


def _fixture_scopes() -> set[str]:
    scopes: set[str] = set()
    for name in ("google", "google-dev"):
        path = REPO_ROOT / "fixtures" / name / "google__oauth_tokens.json"
        if path.exists():
            for grant in json.loads(path.read_text("utf-8"))["grants"]:
                scopes |= set(grant["scopes"])
    return scopes


def test_every_scope_seen_in_a_fixture_is_classified(taxonomy):
    """Including the real dev tenant's. "Unknown" is for scopes nobody has met yet."""
    unclassified = sorted(s for s in _fixture_scopes() if not taxonomy.is_classified(s))
    assert unclassified == []


@pytest.mark.parametrize(
    "scope,tier",
    [
        # Each of these was either mis-tiered once or is the one a client asks about.
        ("https://mail.google.com/", ScopeTier.FULL_DATA_WRITE),
        (G + "gmail.compose", ScopeTier.FULL_DATA_WRITE),  # sends as the user
        (G + "spreadsheets", ScopeTier.FULL_DATA_WRITE),  # edits, not just reads
        (G + "documents", ScopeTier.FULL_DATA_WRITE),
        (G + "calendar.events.readonly", ScopeTier.FULL_DATA_READ),  # every calendar
        (G + "gmail.settings.basic", ScopeTier.FULL_DATA_WRITE),  # forwarding filters
        (G + "cloud-platform", ScopeTier.ADMIN_EQUIVALENT),
        (G + "ediscovery", ScopeTier.ADMIN_EQUIVALENT),  # Vault: everyone's mail
        (G + "admin.directory.user", ScopeTier.ADMIN_EQUIVALENT),
        (G + "admin.directory.user.security", ScopeTier.ADMIN_EQUIVALENT),  # via prefix
        (G + "directory.readonly", ScopeTier.METADATA_ONLY),
        ("openid", ScopeTier.SIGN_IN_ONLY),
    ],
)
def test_pinned_tiers(taxonomy, scope, tier):
    assert taxonomy.tier_for(scope) == tier


def test_a_readonly_scope_never_outranks_its_read_write_sibling(taxonomy):
    for scope in taxonomy.exact:
        for suffix in (".readonly", ".read-only", ".read_only"):
            if scope.endswith(suffix):
                sibling = scope[: -len(suffix)]
                if taxonomy.is_classified(sibling):
                    assert taxonomy.tier_for(scope).weight <= taxonomy.tier_for(sibling).weight, scope


def test_admin_read_only_scopes_are_not_rated_admin_equivalent(taxonomy):
    """The admin prefix catches unlisted admin scopes as administrative. The
    read-only ones we know are listed, so a directory-reading app is not
    reported as able to run the tenant."""
    for suffix in ("user", "group", "orgunit", "domain", "rolemanagement"):
        assert taxonomy.tier_for(f"{G}admin.directory.{suffix}.readonly") == ScopeTier.METADATA_ONLY


def test_google_session_grants_are_device_sign_ins_only_when_alone(taxonomy):
    oauth_login = "https://www.google.com/accounts/OAuthLogin"
    assert taxonomy.first_party_kind("any-id", [oauth_login]) == "device_sign_in"
    # Mixed with an ordinary scope: not a Google session -- handled as a third party.
    assert taxonomy.first_party_kind("any-id", [oauth_login, G + "gmail.readonly"]) is None
    assert taxonomy.first_party_kind("any-id", []) is None


def test_developer_tools_are_matched_by_client_id(taxonomy):
    assert taxonomy.first_party_kind("32555940559.apps.googleusercontent.com") == "developer_tool"


def test_version_was_bumped_for_this_revision(taxonomy):
    assert taxonomy.version >= "2026.09.2"
