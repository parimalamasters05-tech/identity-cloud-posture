"""Snapshot persistence, retention, and the deletion attestation."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from icp.models.snapshot import Snapshot
from icp.security import crypto
from icp.storage.finding_store import FindingStore, deletion_attestation
from icp.storage.retention import KINDS, expired_files, purge
from icp.storage.snapshot_store import SnapshotStore, SnapshotStoreError


@pytest.fixture
def key(monkeypatch) -> str:
    value = crypto.generate_key()
    monkeypatch.setenv("ICP_SNAPSHOT_KEY", value)
    return value


def test_encrypted_round_trip(tmp_path: Path, snapshot: Snapshot, key):
    store = SnapshotStore(tmp_path, encrypt=True)
    path = store.save(snapshot)
    assert path.name.endswith(".json.enc")

    reloaded = store.load(path)
    assert reloaded.snapshot_id == snapshot.snapshot_id
    assert reloaded.artifacts.keys() == snapshot.artifacts.keys()


def test_encrypted_file_does_not_leak_user_data(tmp_path: Path, snapshot: Snapshot, key):
    path = SnapshotStore(tmp_path, encrypt=True).save(snapshot)
    blob = path.read_bytes()
    assert b"departed.finance" not in blob
    assert b"dev-icp.example" not in blob


def test_plaintext_mode_is_explicit_and_readable(tmp_path: Path, snapshot: Snapshot):
    path = SnapshotStore(tmp_path, encrypt=False).save(snapshot)
    assert path.name.endswith(".json")
    assert not path.name.endswith(".enc")
    json.loads(path.read_text("utf-8"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_snapshot_files_are_owner_only(tmp_path: Path, snapshot: Snapshot, key):
    path = SnapshotStore(tmp_path, encrypt=True).save(snapshot)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(tmp_path).stat().st_mode) == 0o700


def test_unchangeable_permissions_do_not_lose_a_collection_run(
    tmp_path: Path, snapshot: Snapshot, key, monkeypatch, caplog
):
    """Docker Desktop bind mounts are root-owned, so chmod raises EPERM there.

    Observed against a real tenant: every collector finished, then the run
    died on `chmod` of /work/snapshots and the snapshot was never written.
    """

    def refuse(self, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted", str(self))

    monkeypatch.setattr(Path, "chmod", refuse)

    store = SnapshotStore(tmp_path, encrypt=True)
    path = store.save(snapshot)

    assert store.load(path).snapshot_id == snapshot.snapshot_id
    if os.name == "posix":
        assert "Restrict access to this folder on the host" in caplog.text


def test_a_swapped_snapshot_file_fails_to_decrypt(tmp_path: Path, snapshot: Snapshot, key):
    """The snapshot ID is bound as AAD, so files cannot be silently substituted."""
    store = SnapshotStore(tmp_path, encrypt=True)
    path = store.save(snapshot)
    impostor = path.with_name(path.name.replace(snapshot.snapshot_id, "20200101T000000Z-deadbeef"))
    path.rename(impostor)
    with pytest.raises(InvalidTag):
        store.load(impostor)


def test_incompatible_schema_is_refused(tmp_path: Path, snapshot: Snapshot):
    """Misreading old client data is worse than failing."""
    store = SnapshotStore(tmp_path, encrypt=False)
    path = store.save(snapshot)
    data = json.loads(path.read_text("utf-8"))
    data["schema_version"] = "99.0"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(SnapshotStoreError, match="incompatible"):
        store.load(path)


def test_tenant_id_cannot_escape_the_snapshot_directory(tmp_path: Path, snapshot: Snapshot):
    hostile = snapshot.model_copy(update={"tenant_id": "../../etc/passwd"})
    store = SnapshotStore(tmp_path, encrypt=False)
    path = store.save(hostile)
    assert path.parent.resolve() == tmp_path.resolve()
    assert ".." not in path.name


def test_load_latest_returns_the_newest(tmp_path: Path, snapshot: Snapshot):
    store = SnapshotStore(tmp_path, encrypt=False)
    older = snapshot.model_copy(update={"snapshot_id": "20260101T000000Z-aaaaaaaa"})
    newer = snapshot.model_copy(update={"snapshot_id": "20260601T000000Z-bbbbbbbb"})
    store.save(older)
    store.save(newer)
    assert store.load_latest(snapshot.tenant_id).snapshot_id == newer.snapshot_id


def test_content_hash_ignores_timestamps(snapshot: Snapshot):
    """Two collections of an unchanged tenant should hash identically."""
    later = snapshot.model_copy(
        update={"collected_at": snapshot.collected_at + timedelta(hours=6), "snapshot_id": "x"}
    )
    assert snapshot.content_hash() == later.content_hash()


# -- findings ------------------------------------------------------------------


def test_findings_file_round_trips(tmp_path: Path, result, matrix):
    store = FindingStore(tmp_path)
    path = store.save(result, tenant_id="dev-icp", snapshot_id="snap-1", matrix=matrix)
    document = json.loads(path.read_text("utf-8"))

    assert document["schema_version"] == "2.2"
    assert document["id_scheme"] == "icp.finding.v2"
    assert "partial_coverage" in document["summary"]
    assert document["summary"]["total"] == len(result.findings)
    assert all("score_breakdown" in f for f in document["findings"])
    assert len(store.load(path)) == len(result.findings)


def test_findings_from_the_old_id_scheme_are_refused_for_comparison(tmp_path: Path, result, matrix):
    """Every v1 ID differs from its v2 twin. Comparing them would report every
    finding resolved and re-opened -- plausible-looking and entirely wrong."""
    from icp.storage.finding_store import IncompatibleFindings

    store = FindingStore(tmp_path)
    path = store.save(result, tenant_id="dev-icp", snapshot_id="snap-1", matrix=matrix)
    document = json.loads(path.read_text("utf-8"))
    document.pop("id_scheme")
    document["schema_version"] = "1.1"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(IncompatibleFindings, match="icp assess --snapshot"):
        store.load(path)


# -- retention -----------------------------------------------------------------

SNAPSHOTS = KINDS[0]
_KEEP_ALL_BUT_SNAPSHOTS = {"snapshots": 30, "audit_trails": None, "findings": None, "reports": None}


def _write(root: Path, stamp: str) -> Path:
    path = root / f"dev-icp__{stamp}-abcd1234.json"
    path.write_bytes(b"{}")
    return path


def _folders(root: Path) -> dict[str, Path]:
    return {"snapshots": root, "output": root}


def test_expired_files_use_the_filename_timestamp(tmp_path: Path):
    """mtime resets when a file is copied between machines; the name does not."""
    now = datetime(2026, 9, 1, tzinfo=UTC)
    old = _write(tmp_path, "20260101T000000Z")
    recent = _write(tmp_path, "20260828T000000Z")
    os.utime(old, None)  # fresh mtime, old name

    expired = expired_files(tmp_path, SNAPSHOTS, retention_days=30, now=now)
    assert old in expired
    assert recent not in expired


def test_purge_deletes_and_reports(tmp_path: Path):
    now = datetime(2026, 9, 1, tzinfo=UTC)
    old = _write(tmp_path, "20260101T000000Z")
    result = purge(_folders(tmp_path), _KEEP_ALL_BUT_SNAPSHOTS, now=now)
    assert result.deleted == {"snapshots": [old.name]}
    assert not old.exists()


def test_dry_run_deletes_nothing(tmp_path: Path):
    now = datetime(2026, 9, 1, tzinfo=UTC)
    old = _write(tmp_path, "20260101T000000Z")
    result = purge(_folders(tmp_path), _KEEP_ALL_BUT_SNAPSHOTS, dry_run=True, now=now)
    assert result.deleted == {"snapshots": [old.name]}
    assert old.exists()


def test_unrecognized_filenames_are_left_alone(tmp_path: Path):
    """Never delete a file this tool did not create."""
    stray = tmp_path / "client-notes.txt"
    stray.write_text("do not delete")
    attestation = tmp_path / "deletion-attestation-20200101T000000Z.json"
    attestation.write_text("{}")
    every_kind = {kind.name: 1 for kind in KINDS}
    purge(_folders(tmp_path), every_kind, now=datetime(2030, 1, 1, tzinfo=UTC))
    assert stray.exists() and attestation.exists()


def test_each_kind_of_file_has_its_own_retention_period(tmp_path: Path):
    """Data handling policy, section 4: snapshots and findings 30 days, API call
    trails 12 months, reports per the engagement letter."""
    snapshots, output = tmp_path / "snapshots", tmp_path / "output"
    snapshots.mkdir()
    output.mkdir()
    old = "20260101T000000000Z-abcd1234"  # 8 months before `now`
    files = {
        "snapshot": snapshots / f"m365__{old}.json.enc",
        "trail": snapshots / f"{old}.apicalls.jsonl",
        "trail manifest": snapshots / f"{old}.apicalls.manifest.json",
        "findings": output / f"m365__{old}__findings.json",
        "delta": output / f"m365__{old}__delta.json",
        "report": output / f"client__combined__{old}.pdf",
    }
    for path in files.values():
        path.write_bytes(b"{}")

    result = purge(
        {"snapshots": snapshots, "output": output},
        {"snapshots": 30, "audit_trails": 365, "findings": 30, "reports": None},
        now=datetime(2026, 9, 1, tzinfo=UTC),
    )
    assert sorted(result.deleted) == ["findings", "snapshots"]
    assert not files["snapshot"].exists() and not files["findings"].exists() and not files["delta"].exists()
    assert files["trail"].exists() and files["trail manifest"].exists()  # kept a year
    assert files["report"].exists()  # kept until ICP_REPORT_RETENTION_DAYS is set

    later = purge(
        {"snapshots": snapshots, "output": output},
        {"snapshots": 30, "audit_trails": 365, "findings": 30, "reports": 180},
        now=datetime(2027, 1, 2, tzinfo=UTC),
    )
    assert sorted(later.deleted) == ["audit_trails", "reports"]
    assert not any(path.exists() for path in files.values())


def test_a_file_that_cannot_be_deleted_is_reported_not_attested(tmp_path: Path, monkeypatch):
    old = _write(tmp_path, "20260101T000000Z")

    def refuse(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(crypto, "secure_delete", refuse)
    result = purge(_folders(tmp_path), _KEEP_ALL_BUT_SNAPSHOTS, now=datetime(2026, 9, 1, tzinfo=UTC))
    assert result.deleted == {}
    assert "Permission denied" in result.failed[old.name]

    attestation = deletion_attestation("dev-icp", result.deleted, retention={}, failed=result.failed)
    assert attestation["file_count"] == 0
    assert attestation["not_deleted"][0]["file"] == old.name


def test_deletion_attestation_records_what_was_destroyed():
    attestation = deletion_attestation(
        "dev-icp",
        {"snapshots": ["a.json"], "findings": ["b.json"]},
        retention={"snapshots": 30, "reports": None},
        operator="P. Nagaraj",
    )
    assert attestation["tenant_id"] == "dev-icp"
    assert attestation["file_count"] == 2
    assert attestation["by_kind"] == {"findings": ["b.json"], "snapshots": ["a.json"]}
    assert attestation["retention_days"] == {"snapshots": 30, "reports": "kept"}
    assert attestation["operator"] == "P. Nagaraj"
    assert "deleted_at" in attestation


def test_deletion_attestation_claims_only_what_purge_does():
    """purge overwrites and unlinks files; it never handles the encryption key."""
    method = deletion_attestation("dev-icp", {}, retention={})["method"]
    assert "overwritten" in method and "unlinked" in method
    assert "key material" not in method
    assert "Encryption keys are not handled" in method


def test_retention_handles_both_timestamp_precisions(tmp_path: Path):
    """Snapshots written by earlier builds used second precision.

    They must still be picked up by retention; a filename this tool no longer
    produces is not a licence for client data to live forever.
    """
    now = datetime(2026, 9, 1, tzinfo=UTC)
    old_seconds = tmp_path / "dev-icp__20260101T000000Z-abcd1234.json"
    old_millis = tmp_path / "dev-icp__20260101T000000123Z-abcd1234.json"
    old_seconds.write_bytes(b"{}")
    old_millis.write_bytes(b"{}")

    expired = expired_files(tmp_path, SNAPSHOTS, retention_days=30, now=now)
    assert set(expired) == {old_seconds, old_millis}


def test_load_latest_is_ordered_by_time_not_by_random_suffix(tmp_path: Path, snapshot: Snapshot):
    """Two collections in the same second must still order correctly.

    Filenames are sorted lexicographically, so without sub-second precision the
    random suffix would decide which snapshot counts as 'latest' -- and
    `icp assess` would silently analyse the earlier one.
    """
    store = SnapshotStore(tmp_path, encrypt=False)
    earlier = snapshot.model_copy(update={"snapshot_id": "20260911T025536001Z-ffffffff"})
    later = snapshot.model_copy(update={"snapshot_id": "20260911T025536999Z-00000000"})
    store.save(earlier)
    store.save(later)
    assert store.load_latest(snapshot.tenant_id).snapshot_id == later.snapshot_id


def test_non_snapshot_files_are_ignored(tmp_path: Path, snapshot: Snapshot):
    """Operators reasonably point the snapshot and output directories at one folder.

    Without a filename check, `icp report` would pick up a findings file, fail
    schema validation, and show the operator a pydantic traceback instead of a
    report.
    """
    store = SnapshotStore(tmp_path, encrypt=False)
    store.save(snapshot)

    (tmp_path / f"{snapshot.tenant_id}__20260911T010203004Z-aaaaaaaa__findings.json").write_text("{}")
    (tmp_path / f"{snapshot.tenant_id}__20260911T010203004Z-aaaaaaaa.apicalls.jsonl").write_text("")
    (tmp_path / "notes.json").write_text("{}")

    listed = store.list_snapshots(snapshot.tenant_id)
    assert len(listed) == 1
    assert store.load_latest(snapshot.tenant_id).snapshot_id == snapshot.snapshot_id
