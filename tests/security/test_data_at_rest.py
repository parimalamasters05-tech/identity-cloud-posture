"""Client data at rest: encrypted unless a test tenant, owner-only on disk.

Each test pins a control that used to depend on the operator: a plaintext
live snapshot with one flag, and findings, call trails, deltas and reports
left with whatever mode the umask gave them.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner

from icp.cli import _encrypt_live, cli
from icp.config import Settings
from icp.storage import _permissions
from icp.storage._permissions import write_private

pytestmark = pytest.mark.security

posix_only = pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.parametrize(
    ("encrypt_at_rest", "no_encrypt"),
    [(False, False), (True, True)],
    ids=["ICP_ENCRYPT_AT_REST=false", "--no-encrypt"],
)
def test_a_live_snapshot_is_never_plaintext_outside_a_test_tenant(encrypt_at_rest, no_encrypt):
    settings = Settings(encrypt_at_rest=encrypt_at_rest, test_environment=False)
    with pytest.raises(SystemExit):
        _encrypt_live(settings, no_encrypt)


def test_a_test_tenant_may_be_written_in_plaintext():
    assert _encrypt_live(Settings(encrypt_at_rest=False, test_environment=True), False) is False
    assert _encrypt_live(Settings(test_environment=True), False) is True  # encryption on stays on


def test_collect_aws_refuses_plaintext_before_writing_anything(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ICP_SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    monkeypatch.delenv("ICP_TEST_ENVIRONMENT", raising=False)
    prowler = Path(__file__).resolve().parents[2] / "fixtures" / "aws" / "prowler-lab.ocsf.json"
    if not prowler.exists():
        pytest.skip("no Prowler fixture")
    result = CliRunner().invoke(
        cli,
        ["collect-aws", "--prowler-output", str(prowler), "--keep-prowler-output", "--no-encrypt"],
        obj={},
    )
    assert result.exit_code == 1
    assert "ICP_TEST_ENVIRONMENT=true" in result.output
    assert not list((tmp_path / "snapshots").glob("*"))


@posix_only
def test_written_files_are_owner_only_even_under_a_permissive_umask(tmp_path: Path):
    old = os.umask(0o000)
    try:
        path = write_private(tmp_path / "report.html", "<p>names</p>")
    finally:
        os.umask(old)
    assert _mode(path) == 0o600


@posix_only
def test_rewriting_a_world_readable_file_closes_it(tmp_path: Path):
    path = tmp_path / "findings.json"
    path.write_text("{}")
    path.chmod(0o644)
    write_private(path, "{}")
    assert _mode(path) == 0o600


@posix_only
def test_every_client_data_writer_leaves_owner_only_files(tmp_path: Path, monkeypatch):
    """Reports, findings, call trails and their manifests, via the real writers."""
    from datetime import UTC, datetime

    from icp.models.snapshot import ApiCallRecord
    from icp.security.audit_log import write_audit_trail

    old = os.umask(0o022)
    try:
        trail = write_audit_trail(
            tmp_path / "trails" / "20261027T000000000Z-abcd1234.apicalls.jsonl",
            [
                ApiCallRecord(
                    method="GET",
                    url="https://graph.microsoft.com/v1.0/users",
                    status=200,
                    at=datetime.now(UTC),
                )
            ],
            tenant_id="m365",
        )
        monkeypatch.chdir(Path(__file__).resolve().parents[2])
        monkeypatch.setenv("ICP_TENANT_ID", "dev-icp")
        monkeypatch.setenv("ICP_SNAPSHOT_DIR", str(tmp_path / "snapshots"))
        monkeypatch.setenv("ICP_OUTPUT_DIR", str(tmp_path / "output"))
        runner = CliRunner()
        for args in (
            ["collect", "--fixtures"],
            ["assess"],
            ["report", "--client-name", "C", "--assessor", "A", "--allow-stale"],
        ):
            assert runner.invoke(cli, args, obj={}).exit_code == 0, args
    finally:
        os.umask(old)

    written = [trail, trail.with_suffix(".manifest.json"), *(tmp_path / "output").iterdir()]
    assert any(p.name.endswith("__findings.json") for p in written)
    assert any(p.suffix == ".html" for p in written)
    for path in written:
        assert _mode(path) == 0o600, path.name
    assert _mode(tmp_path / "output") == 0o700


def test_a_folder_that_cannot_be_restricted_is_warned_about_once(tmp_path: Path, monkeypatch, caplog):
    """A Docker Desktop bind mount: one warning per folder, not one per file."""
    monkeypatch.setattr(_permissions.os, "name", "posix")
    monkeypatch.setattr(_permissions, "_warned", set())

    def refuse(self, mode):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(Path, "chmod", refuse)
    with caplog.at_level(logging.WARNING, logger="icp.storage._permissions"):
        for name in ("a.html", "a.pdf", "b.json"):
            write_private(tmp_path / name, "x")
    assert len([r for r in caplog.records if "Restrict access" in r.getMessage()]) == 1


def test_a_host_folder_checked_by_run_all_is_noted_not_warned(tmp_path: Path, monkeypatch, caplog):
    monkeypatch.setattr(_permissions.os, "name", "posix")
    monkeypatch.setattr(_permissions, "_warned", set())
    monkeypatch.setenv("ICP_HOST_FOLDERS_VERIFIED", "true")

    def refuse(self, mode):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(Path, "chmod", refuse)
    with caplog.at_level(logging.INFO, logger="icp.storage._permissions"):
        write_private(tmp_path / "a.html", "x")
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("checked by run-all.ps1" in r.getMessage() for r in caplog.records)
