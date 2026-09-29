"""Validating a delta against its snapshots.

Run live on the dev tenant on 29 Sep 2026: developer-tool logins were removed,
both snapshots were re-assessed offline, and the re-derived delta matched the
saved one (1 resolved, GWS-SVC-003).
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from icp.delta.validate import _fingerprint, rederive, validate
from icp.normalizers.google import normalize
from icp.rules import assess
from icp.storage.finding_store import FindingStore


def _saved(snapshot, tmp_path: Path, name: str):
    """What `icp assess` writes, read back as `icp delta` reads it."""
    store = FindingStore(tmp_path / name)
    result = assess(normalize(snapshot), now=snapshot.collected_at)
    return store.load(store.save(result, tenant_id=snapshot.tenant_id, snapshot_id=snapshot.snapshot_id))


def _fixed_public_files(snapshot):
    """The same tenant after every public link was closed."""
    artifacts = {**snapshot.artifacts, "google.public_drive_items": []}
    return snapshot.model_copy(
        update={
            "artifacts": artifacts,
            "snapshot_id": snapshot.snapshot_id + "-after",
            "collected_at": snapshot.collected_at + timedelta(days=1),
        }
    )


def test_a_real_remediation_validates(snapshot, tmp_path):
    after = _fixed_public_files(snapshot)
    checks, summary = validate(
        snapshot, after, _saved(snapshot, tmp_path, "a"), _saved(after, tmp_path, "b")
    )
    assert all(c.passed for c in checks), [c for c in checks if not c.passed]
    assert summary["resolved"] == 1
    assert summary["new"] == 0


def test_a_saved_file_that_does_not_match_its_snapshot_fails_and_names_the_finding(snapshot, tmp_path):
    after = _fixed_public_files(snapshot)
    tampered = _saved(after, tmp_path, "b")
    dropped = tampered.pop(0)  # a finding silently missing from the saved file

    checks, _ = validate(snapshot, after, _saved(snapshot, tmp_path, "a"), tampered)

    [failed] = [c for c in checks if not c.passed and "current snapshot" in c.label]
    assert dropped.finding_id in failed.detail
    assert not next(c for c in checks if c.label.startswith("delta")).passed


def test_a_snapshot_is_judged_as_of_its_collection_not_today(snapshot):
    """Found while building this check: `icp assess` used today's date, so a
    months-old snapshot re-assessed later could change its own findings
    ("dormant 90 days" measured to the wrong day)."""
    as_collected = sorted(map(_fingerprint, rederive(snapshot)))
    a_year_later = sorted(
        map(
            _fingerprint,
            assess(normalize(snapshot), now=snapshot.collected_at + timedelta(days=400)).findings,
        )
    )
    assert as_collected == sorted(
        map(_fingerprint, assess(normalize(snapshot), now=snapshot.collected_at).findings)
    )
    assert as_collected != a_year_later, (
        "the fixture should have age-based findings that move with the clock"
    )


def test_the_assess_command_uses_the_collection_time():
    import inspect

    from icp import cli

    assert "now=snapshot.collected_at" in inspect.getsource(cli.assess.callback)
