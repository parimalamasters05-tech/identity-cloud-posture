"""Normalization is where every Google quirk gets handled exactly once.

If one of these regresses, the bug appears in `rules/` as a mysterious false
positive, so they are asserted here rather than discovered there.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from icp.models.enums import Assessability, CheckFamily, IdentityKind, ScopeTier
from icp.models.snapshot import CollectionError, Snapshot
from icp.normalizers.google import _parse_time, normalize
from icp.risk.scope_taxonomy import ScopeTaxonomy

# -- timestamp handling --------------------------------------------------------


def test_epoch_sentinel_means_never_signed_in():
    """Google returns 1970-01-01 for 'never'.

    Reading that literally would make every unused account look ancient *and*
    active -- exactly backwards, and it would put new starters at the top of the
    dormancy finding.
    """
    assert _parse_time("1970-01-01T00:00:00.000Z") is None


def test_real_timestamps_parse():
    parsed = _parse_time("2026-05-14T09:30:00.000Z")
    assert parsed == datetime(2026, 5, 14, 9, 30, tzinfo=UTC)


@pytest.mark.parametrize("value", [None, "", "not-a-date", 12345, []])
def test_malformed_timestamps_degrade_to_none(value):
    assert _parse_time(value) is None


# -- identity normalization ----------------------------------------------------


def test_users_and_groups_are_separated(tenant):
    assert all(u.kind == IdentityKind.USER for u in tenant.users)
    groups = [i for i in tenant.identities if i.kind == IdentityKind.GROUP]
    assert len(groups) == 2


def test_suspended_users_are_excluded_from_active(tenant):
    assert len(tenant.users) == 34
    assert len(tenant.active_users) == 32


def test_super_admin_flag_and_role_assignment_agree(tenant):
    labels = {u.primary_email for u in tenant.super_admins}
    assert labels == {
        "dana.reyes@dev-icp.example",
        "sam.okafor@dev-icp.example",
        "former.consultant@dev-icp.example",
    }


def test_delegated_admin_counts_as_privileged_but_not_super(tenant):
    priya = next(u for u in tenant.users if u.primary_email.startswith("priya"))
    assert priya.is_privileged
    assert priya.is_delegated_admin
    assert not priya.is_super_admin


def test_security_key_count_drives_phishing_resistance(tenant):
    dana = next(u for u in tenant.users if u.primary_email.startswith("dana"))
    assert dana.has_phishing_resistant_mfa

    enrolled_without_key = next(
        u for u in tenant.users if u.mfa_enrolled and u.primary_email.startswith("priya")
    )
    assert not enrolled_without_key.has_phishing_resistant_mfa


# -- OAuth normalization -------------------------------------------------------


def test_grants_are_one_per_user_application_pair(tenant):
    assert len(tenant.grants) == 38


def test_scope_tiers_are_classified(tenant):
    notetaker = [g for g in tenant.grants if g.app_name == "NoteTaker AI"]
    assert notetaker
    assert notetaker[0].max_tier == ScopeTier.FULL_DATA_WRITE


def test_sign_in_only_app_is_classified_as_harmless(tenant):
    payroll = [g for g in tenant.grants if g.app_name == "Payroll Portal"]
    assert payroll
    assert all(g.max_tier == ScopeTier.SIGN_IN_ONLY for g in payroll)


def test_anonymous_app_flag_survives_normalization(tenant):
    assert any(g.is_anonymous_app for g in tenant.grants)


def test_token_log_dates_join_onto_the_right_grant(tenant):
    inbox = next(g for g in tenant.grants if g.app_name == "InboxCleaner Pro")
    assert inbox.last_used_at is not None and inbox.last_used_at.date().isoformat() == "2026-04-04"
    assert (
        inbox.last_authorized_at is not None and inbox.last_authorized_at.date().isoformat() == "2026-03-15"
    )

    # Same user, different app: dates must not leak across the join.
    kim_notetaker = next(
        g for g in tenant.grants if g.app_name == "NoteTaker AI" and g.user_email.startswith("kim.larsen")
    )
    assert kim_notetaker.last_used_at.date().isoformat() == "2026-08-30"


def test_token_log_coverage_is_the_full_window_when_not_truncated(tenant):
    log = tenant.token_log
    assert log is not None and log.activity_recorded and not log.truncated
    assert log.covered_since.date().isoformat() == "2026-03-05"


def test_every_connected_app_is_in_the_inventory_once(tenant):
    """Flagged or not: the inventory is what lets a client spot the app nobody knows."""
    names = [a.name for a in tenant.applications]
    assert len(names) == len({g.client_id for g in tenant.grants})
    assert "Payroll Portal" in names  # never a finding, still listed

    notetaker = next(a for a in tenant.applications if a.name == "NoteTaker AI")
    assert (notetaker.active_users, notetaker.suspended_users) == (12, 1)
    assert notetaker.max_tier == ScopeTier.FULL_DATA_WRITE


def test_inventory_is_ordered_by_blast_radius(tenant):
    weights = [a.max_tier.weight for a in tenant.applications]
    assert weights == sorted(weights, reverse=True)


def test_a_snapshot_without_the_token_log_still_normalizes(snapshot):
    """Every snapshot taken before this collector existed."""
    from icp.normalizers.google import normalize

    artifacts = {k: v for k, v in snapshot.artifacts.items() if k != "google.token_activity"}
    tenant = normalize(snapshot.model_copy(update={"artifacts": artifacts}))
    assert tenant.token_log is None
    assert all(g.last_used_at is None for g in tenant.grants)
    assert tenant.applications


# -- scope taxonomy ------------------------------------------------------------


def test_exact_match_wins_over_prefix():
    taxonomy = ScopeTaxonomy.load_default()
    exact = "https://www.googleapis.com/auth/admin.directory.user.readonly"
    assert taxonomy.tier_for(exact) == ScopeTier.METADATA_ONLY


def test_prefix_match_catches_unlisted_admin_scopes():
    """Default to treating an unknown Admin SDK scope as administrative."""
    taxonomy = ScopeTaxonomy.load_default()
    tier = taxonomy.tier_for("https://www.googleapis.com/auth/admin.something.new")
    assert tier == ScopeTier.ADMIN_EQUIVALENT


def test_unknown_scope_is_recorded_not_silently_ignored():
    taxonomy = ScopeTaxonomy.load_default()
    assert taxonomy.tier_for("https://example.com/auth/mystery") == ScopeTier.UNKNOWN
    assert "https://example.com/auth/mystery" in taxonomy.unclassified


def test_unknown_is_weighted_mid_range():
    """An unclassified scope is a research task, not a pass."""
    assert ScopeTier.SIGN_IN_ONLY.weight < ScopeTier.UNKNOWN.weight
    assert ScopeTier.UNKNOWN.weight < ScopeTier.ADMIN_EQUIVALENT.weight


def test_every_taxonomy_entry_has_a_description():
    """Descriptions are printed in the client report."""
    taxonomy = ScopeTaxonomy.load_default()
    for scope, record in taxonomy.exact.items():
        assert record["description"], f"{scope} has no description"


# -- degradation ---------------------------------------------------------------


def test_a_degraded_collector_marks_its_families_unassessable(snapshot: Snapshot):
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
    tenant = normalize(degraded)
    assert not tenant.is_assessable(CheckFamily.OAUTH_GRANTS)
    assert not tenant.is_assessable(CheckFamily.SERVICE_ACCOUNT_PRIVILEGE)
    assert tenant.is_assessable(CheckFamily.MFA_COVERAGE)


def test_missing_artifacts_do_not_crash_normalization():
    """A tenant where most collectors failed must still produce a usable view."""
    bare = Snapshot(snapshot_id="s", tenant_id="t", platform="google_workspace", artifacts={})
    tenant = normalize(bare)
    assert tenant.identities == []
    assert tenant.grants == []


def test_coverage_records_oauth_enumeration_completeness(tenant):
    assert tenant.coverage["oauth_coverage_pct"] == 100.0
    assert tenant.coverage["users_active"] == 32
