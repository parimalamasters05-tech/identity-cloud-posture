"""File names built from tenant labels and snapshot IDs stay inside their folder.

A snapshot ID is read back from the snapshot file, so a crafted or corrupted
snapshot must not be able to name where its findings, call trail or report
are written.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from icp.models.enums import Platform
from icp.models.snapshot import Snapshot
from icp.storage.finding_store import FindingStore
from icp.storage.paths import UnsafePathError, component, file_in
from icp.storage.snapshot_store import SnapshotStore

pytestmark = pytest.mark.security

TRAVERSALS = ["../../outside", "..", "a/b", "a\\b", ".hidden", "", "x..y", "/etc/passwd", "C:evil"]


@pytest.mark.parametrize("value", ["20261027T061703806Z-c165c41a", "snap-1", "dev_fixture.2"])
def test_real_ids_and_labels_are_accepted(value):
    assert component(value, "Snapshot ID") == value


@pytest.mark.parametrize("value", TRAVERSALS)
def test_a_name_part_that_could_leave_its_folder_is_refused(value):
    with pytest.raises(UnsafePathError):
        component(value, "Snapshot ID")


def test_a_path_must_resolve_directly_inside_its_folder(tmp_path: Path):
    assert file_in(tmp_path, "a__b__findings.json") == tmp_path / "a__b__findings.json"
    for name in ("../x.json", "sub/x.json", ".."):
        with pytest.raises(UnsafePathError):
            file_in(tmp_path, name)


def test_findings_cannot_be_written_outside_the_output_folder(tmp_path: Path):
    """The review's case: ../../outside as the snapshot ID."""
    store = FindingStore(tmp_path / "output")
    with pytest.raises(UnsafePathError):
        store.path_for("dev", "../../outside")
    # A tenant label is cleaned, as snapshot names have always done.
    assert store.path_for("../../x", "snap-1").parent == tmp_path / "output"


def test_a_snapshot_with_a_crafted_id_is_not_saved_nor_given_a_call_trail(tmp_path: Path):
    snapshot = Snapshot(snapshot_id="../../outside", tenant_id="dev", platform=Platform.GOOGLE_WORKSPACE)
    store = SnapshotStore(tmp_path / "snapshots", encrypt=False)
    with pytest.raises(UnsafePathError):
        store.save(snapshot)
    with pytest.raises(UnsafePathError):
        store.trail_path_for(snapshot)
    assert not list(tmp_path.rglob("*outside*"))
