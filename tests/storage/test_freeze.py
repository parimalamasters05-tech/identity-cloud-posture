"""Freezing a snapshot into fixtures: nothing identifying out, every finding kept."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from tests.conftest import FIXTURE_NOW

from icp.collectors.google import load_fixture_snapshot
from icp.models.enums import Assessability
from icp.models.snapshot import CollectionError
from icp.normalizers.google import normalize
from icp.rules import assess
from icp.storage.freeze import MANIFEST_NAME, FreezeLeak, freeze

pytestmark = pytest.mark.security

REAL_DOMAIN = "dev-icp.example"


def _shape(result) -> Counter:
    """What a report says, minus who it names: rule, severity, how many."""
    return Counter((f.rule_id, f.severity, f.entity_count) for f in result.findings)


def test_pseudonymizing_changes_no_finding(snapshot, matrix, tmp_path: Path):
    """Aliases are applied consistently, so every join -- grant to user, role
    assignment to user, MFA row to user -- still resolves."""
    freeze(snapshot, tmp_path)
    frozen = load_fixture_snapshot(tmp_path)

    before = assess(normalize(snapshot), matrix=matrix, now=FIXTURE_NOW)
    after = assess(normalize(frozen), matrix=matrix, now=FIXTURE_NOW)
    assert _shape(after) == _shape(before)


def test_no_email_name_or_domain_survives(snapshot, tmp_path: Path):
    freeze(snapshot, tmp_path)
    blob = "\n".join(p.read_text("utf-8") for p in tmp_path.glob("*.json")).lower()

    assert REAL_DOMAIN not in blob
    for user in snapshot.artifacts["google.users"]:
        assert user["primaryEmail"].lower() not in blob
        assert user["name"]["fullName"].lower() not in blob
        assert user["id"] not in blob
    for item in snapshot.artifacts["google.public_drive_items"]:
        assert item["name"].lower() not in blob


def test_what_the_rules_need_is_kept(snapshot, tmp_path: Path):
    freeze(snapshot, tmp_path)
    frozen = load_fixture_snapshot(tmp_path)
    grants = frozen.artifacts["google.oauth_tokens"]["grants"]

    # First-party detection is by client ID; app names are the report's subject.
    assert any(g["clientId"] == "32555940559.apps.googleusercontent.com" for g in grants)
    assert any(g["displayText"] == "NoteTaker AI" for g in grants)
    assert frozen.artifacts["google.users"][0]["lastLoginTime"]


def test_a_name_hidden_in_an_unexpected_field_blocks_the_write(snapshot, tmp_path: Path):
    """An app a user named after themselves: the freeze does not know that
    field holds a name, so the leak scan is what catches it."""
    grants = snapshot.artifacts["google.oauth_tokens"]["grants"]
    leaky = [{**grants[0], "displayText": "Sam Okafor's inbox helper"}, *grants[1:]]
    artifacts = {
        **snapshot.artifacts,
        "google.oauth_tokens": {**snapshot.artifacts["google.oauth_tokens"], "grants": leaky},
    }
    out = tmp_path / "out"

    with pytest.raises(FreezeLeak):
        freeze(snapshot.model_copy(update={"artifacts": artifacts}), out)
    assert not out.exists(), "a leak must write nothing"


def test_degraded_collectors_are_frozen_as_degraded(snapshot, tmp_path: Path):
    """Dropping the error would turn "could not be read" into "nothing found"."""
    artifacts = {k: v for k, v in snapshot.artifacts.items() if k != "google.mfa"}
    error = CollectionError(
        collector="google.mfa",
        assessability=Assessability.NOT_ASSESSABLE_LICENSE,
        message="No populated 2SV usage report for sam.okafor@dev-icp.example",
    )
    freeze(snapshot.model_copy(update={"artifacts": artifacts, "errors": (error,)}), tmp_path)

    frozen = load_fixture_snapshot(tmp_path)
    assert frozen.degraded_collectors() == ("google.mfa",)
    assert REAL_DOMAIN not in frozen.errors[0].message
    assert "google.mfa" not in frozen.artifacts


def test_manifest_is_not_loaded_as_an_artifact(snapshot, tmp_path: Path):
    freeze(snapshot, tmp_path)
    assert (tmp_path / MANIFEST_NAME).exists()
    assert not any(k.startswith("_") for k in load_fixture_snapshot(tmp_path).artifacts)


def test_refreezing_removes_artifacts_the_new_snapshot_lacks(snapshot, tmp_path: Path):
    freeze(snapshot, tmp_path)
    smaller = {k: v for k, v in snapshot.artifacts.items() if k != "google.groups"}
    freeze(snapshot.model_copy(update={"artifacts": smaller}), tmp_path)

    assert "google.groups" not in load_fixture_snapshot(tmp_path).artifacts


def test_service_account_client_ids_and_names_are_replaced(snapshot, tmp_path: Path):
    """The assessment's own service account appears in the token log on every
    run. Its numeric client ID and name identify the client's cloud project."""
    log = snapshot.artifacts["google.token_activity"]
    real_id = next(a["client_id"] for a in log["apps"] if a["client_id"].isdigit())
    real_name = next(a["app_name"] for a in log["apps"] if a["client_id"] == real_id)
    freeze(snapshot, tmp_path)
    blob = (tmp_path / "google__token_activity.json").read_text("utf-8")

    assert real_id not in blob and real_name not in blob
    assert "Service account 01" in blob
    # Published apps keep their IDs: first-party detection matches on them.
    assert "884411223344.apps.googleusercontent.com" in blob


def test_a_department_named_with_an_ordinary_word_does_not_block_the_freeze(snapshot, tmp_path: Path):
    """Found freezing the dev tenant: the department "/Test-Locked" matched
    Google's permission name GROUPS_MANAGE_LOCKED_LABEL and the freeze refused."""
    users = [
        {**u, "orgUnitPath": "/Test-Locked"} if i == 0 else u
        for i, u in enumerate(snapshot.artifacts["google.users"])
    ]
    roles = [
        {**r, "rolePrivileges": [*r["rolePrivileges"], {"privilegeName": "GROUPS_MANAGE_LOCKED_LABEL"}]}
        for r in snapshot.artifacts["google.roles"]
    ]
    changed = snapshot.model_copy(
        update={"artifacts": {**snapshot.artifacts, "google.users": users, "google.roles": roles}}
    )
    freeze(changed, tmp_path)  # must not raise

    blob = (tmp_path / "google__users.json").read_text("utf-8")
    assert "/Test-Locked" not in blob and "/unit01" in blob


def test_aliases_are_stable_across_freezes(snapshot, tmp_path: Path):
    """Re-freezing an unchanged tenant must not churn every fixture file."""
    freeze(snapshot, tmp_path / "a")
    freeze(snapshot, tmp_path / "b")
    for path in (tmp_path / "a").glob("google__*.json"):
        assert path.read_text("utf-8") == (tmp_path / "b" / path.name).read_text("utf-8")
