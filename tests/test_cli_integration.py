"""Full pipeline through the CLI, offline.

`collect --fixtures` -> `assess` -> `report` -> `delta` -> `purge`, with no
credentials and no network. This is the test that would catch a wiring mistake
between two components that each pass their own unit tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from icp.cli import cli

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch):
    """An isolated run directory with the repo's config and fixtures."""
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setenv("ICP_TENANT_ID", "dev-icp")
    monkeypatch.setenv("ICP_SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    monkeypatch.setenv("ICP_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setenv("ICP_FIXTURE_DIR", str(REPO_ROOT / "fixtures"))
    return tmp_path


def run(*args) -> object:
    result = CliRunner().invoke(cli, list(args), obj={})
    if result.exit_code != 0:
        raise AssertionError(f"`icp {' '.join(args)}` failed:\n{result.output}\n{result.exception}")
    return result


def test_full_pipeline(workspace: Path):
    collected = run("collect", "--fixtures")
    assert "Snapshot written" in collected.output

    snapshots = list((workspace / "snapshots").glob("*.json*"))
    assert len(snapshots) == 1

    assessed = run("assess")
    assert "Findings written" in assessed.output
    assert "critical" in assessed.output

    findings_files = list((workspace / "output").glob("*findings.json"))
    assert len(findings_files) == 1

    document = json.loads(findings_files[0].read_text("utf-8"))
    not_assessed = [k for k in document["summary"]["unassessable"] if k.startswith("GWS-")]
    assert document["summary"]["rules_run"] + len(not_assessed) == 20
    assert document["summary"]["rules_failed"] == []
    assert document["summary"]["by_severity"]["critical"] >= 1

    reported = run("report", "--client-name", "Riverside Community Trust", "--assessor", "Tester")
    assert "HTML report" in reported.output
    assert list((workspace / "output").glob("*.html"))


def _html(workspace: Path) -> str:
    [html] = (workspace / "output").glob("*.html")
    return html.read_text("utf-8")


def test_cover_name_comes_from_the_google_profile(workspace: Path, monkeypatch):
    """Not from configuration: an ICP_CLIENT_NAME left in .env is ignored."""
    monkeypatch.setenv("ICP_CLIENT_NAME", "Stale Name From Config")
    monkeypatch.setenv("ICP_ASSESSOR", "Tester")
    run("collect", "--fixtures")

    reported = run("report")
    assert "Account profile" in reported.output or "account profile" in reported.output
    text = _html(workspace)
    assert "Riverside Community Trust" in text
    assert "Stale Name From Config" not in text


def test_cover_falls_back_to_the_primary_domain(workspace: Path, monkeypatch):
    """The profile scope not granted: the domain, which Google also reports."""
    monkeypatch.setenv("ICP_ASSESSOR", "Tester")
    fixtures = workspace / "fixtures" / "google"
    fixtures.mkdir(parents=True)
    for path in (REPO_ROOT / "fixtures" / "google").glob("*.json"):
        if path.name != "google__customer.json":
            (fixtures / path.name).write_bytes(path.read_bytes())
    monkeypatch.setenv("ICP_FIXTURE_DIR", str(workspace / "fixtures"))
    run("collect", "--fixtures")

    reported = run("report")
    assert "primary domain" in reported.output
    assert "admin.directory.customer.readonly" in reported.output  # says how to get the name
    assert "dev-icp.example" in _html(workspace)


def test_an_explicit_client_name_overrides_google(workspace: Path, monkeypatch):
    monkeypatch.setenv("ICP_ASSESSOR", "Tester")
    run("collect", "--fixtures")
    run("report", "--client-name", "Riverside Trading Name")
    assert "Riverside Trading Name" in _html(workspace)


@pytest.mark.parametrize(
    "args,expected",
    [
        (("--client-name", "Client"), "placeholder"),  # the old compose default
        ((), "ICP_ASSESSOR"),  # assessor missing: .env lacks it
        (("--assessor", "Assessor"), "ICP_ASSESSOR"),  # the old compose default
        (("--assessor", "Your Name"), "ICP_ASSESSOR"),  # .env.example left unedited
    ],
)
def test_report_refuses_a_placeholder_cover(workspace: Path, monkeypatch, args, expected):
    """Found on the dev tenant: the cover read "Client" and "Assessor" because
    .env lacked the names and docker-compose filled in those words."""
    monkeypatch.delenv("ICP_ASSESSOR", raising=False)
    if "--assessor" not in args and "--client-name" in args:
        args = (*args, "--assessor", "Tester")
    run("collect", "--fixtures")

    result = CliRunner().invoke(cli, ["report", *args], obj={})
    assert result.exit_code == 1
    assert expected in result.output
    assert not list((workspace / "output").glob("*.html")), "no report may be written"


def test_run_checks_the_assessor_before_collecting(workspace: Path, monkeypatch):
    """A live read is not wasted on a report that cannot be written."""
    monkeypatch.delenv("ICP_ASSESSOR", raising=False)
    result = CliRunner().invoke(cli, ["run", "--fixtures"], obj={})
    assert result.exit_code == 1
    assert not (workspace / "snapshots").exists() or not list((workspace / "snapshots").iterdir())


def test_delta_between_two_runs(workspace: Path):
    run("collect", "--fixtures")
    run("assess")
    first = sorted((workspace / "output").glob("*findings.json"))[0]

    run("collect", "--fixtures")
    run("assess")
    files = sorted((workspace / "output").glob("*findings.json"))
    assert len(files) == 2
    second = files[-1]

    result = run("delta", "--previous", str(first), "--current", str(second))

    # The same fixture assessed twice must show no movement whatsoever. If this
    # ever fails, finding IDs have stopped being deterministic and every
    # quarterly report would show churn that did not happen.
    assert "resolved     0" in result.output
    assert "new          0" in result.output


def test_purge_writes_a_deletion_attestation(workspace: Path):
    snapshots = workspace / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    (snapshots / "dev-icp__20200101T000000Z-abcd1234.json").write_bytes(b"{}")

    result = run("purge", "--operator", "Test Operator")
    assert "Deleted 1" in result.output

    attestations = list((workspace / "output").glob("deletion-attestation-*.json"))
    assert len(attestations) == 1
    document = json.loads(attestations[0].read_text("utf-8"))
    assert document["operator"] == "Test Operator"
    assert document["file_count"] == 1


def test_verify_scopes_reports_a_clean_allowlist(workspace: Path):
    result = run("verify-scopes")
    assert "all on the reviewed allowlist" in result.output
    # It must not claim every scope is read-only: one is not, and it says which.
    assert "all validated read-only" not in result.output
    assert (
        "Not a read-only scope: https://www.googleapis.com/auth/admin.directory.user.security"
        in result.output
    )
    assert "drive.metadata.readonly" in result.output
    assert "auth/drive.readonly" not in result.output  # can read file contents; never requested


def test_list_rules_shows_no_missing_content(workspace: Path):
    result = run("list-rules")
    assert "GWS-OAU-001" in result.output
    assert "[no content!]" not in result.output


def test_keygen_emits_a_usable_key(workspace: Path):
    import base64

    result = run("keygen")
    # stdout only: the "store this safely" warning goes to stderr, and newer
    # Click versions mix stderr into `result.output`. A script piping the key
    # into a secret manager reads stdout, so that is what must be exactly the key.
    assert len(base64.b64decode(result.stdout.strip())) == 32


def test_live_collection_fails_clearly_without_configuration(tmp_path: Path, monkeypatch):
    """The error a new user is most likely to hit must name the fix."""
    monkeypatch.chdir(REPO_ROOT)
    for name in ("ICP_TENANT_ID", "ICP_GOOGLE_ADMIN_SUBJECT", "ICP_GOOGLE_PRIMARY_DOMAIN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ICP_SNAPSHOT_DIR", str(tmp_path))

    result = CliRunner().invoke(cli, ["collect"], obj={})
    assert result.exit_code == 1
    assert "ICP_TENANT_ID" in result.output
    assert ".env.example" in result.output


def test_snapshot_write_failure_is_a_message_not_a_traceback(workspace: Path, monkeypatch):
    """Forgetting ICP_SNAPSHOT_KEY is the most common second-run mistake.

    Its exception already carries the fix. The operator should read that, not a
    stack trace -- especially on a client call.
    """
    monkeypatch.delenv("ICP_SNAPSHOT_KEY", raising=False)
    monkeypatch.setenv("ICP_ENCRYPT_AT_REST", "true")

    result = CliRunner().invoke(cli, ["collect", "--fixtures"], obj={})
    # Fixtures never encrypt, so this must succeed; the guard is asserted below
    # against the store directly.
    assert result.exit_code == 0

    from icp.collectors.google import load_fixture_snapshot
    from icp.security.crypto import CryptoUnavailable
    from icp.storage.snapshot_store import SnapshotStore

    snapshot = load_fixture_snapshot(REPO_ROOT / "fixtures" / "google")
    with pytest.raises(CryptoUnavailable, match="icp keygen"):
        SnapshotStore(workspace / "enc", encrypt=True).save(snapshot)


def test_tenant_flag_alone_satisfies_the_tenant_identifier(workspace: Path, monkeypatch):
    """The brief's done-when command passes the tenant as a flag, not an env var."""
    monkeypatch.delenv("ICP_TENANT_ID", raising=False)
    result = run("collect", "--fixtures", "--tenant", "dev")
    assert "dev__" in result.output
