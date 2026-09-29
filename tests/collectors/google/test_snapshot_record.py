"""What the snapshot records about the run itself.

The report's methodology page quotes these fields to the client, so each one is
a claim: the scopes we used, when we collected, which build did it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

import icp
from icp.collectors import google as google_collectors
from icp.collectors.base import Collector, CollectorError
from icp.config import Settings
from icp.models.enums import Assessability
from icp.models.snapshot import Snapshot
from icp.security.credentials import CredentialError

POLICIES = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"


class _FakeClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.truncations: list[str] = []
        self.calls: list = []

    def authenticate(self) -> None:
        pass

    def attest_read_only(self) -> None:
        pass


class _Works(Collector):
    name = "google.users"
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.user.readonly",)

    def collect(self, client):
        return [{"id": "1"}]


class _Refused(Collector):
    name = "google.workspace_policies"
    required_scopes = (POLICIES,)

    def collect(self, client):
        raise CollectorError(
            "not delegated", Assessability.NOT_ASSESSABLE_PERMISSION, refused_scopes=(POLICIES,)
        )


@pytest.fixture
def live_settings(monkeypatch) -> Settings:
    monkeypatch.setenv("ICP_TENANT_ID", "dev")
    monkeypatch.setenv("ICP_GOOGLE_ADMIN_SUBJECT", "icp-assessment@dev.example")
    monkeypatch.setenv("ICP_GOOGLE_PRIMARY_DOMAIN", "dev.example")
    monkeypatch.setattr(google_collectors, "GoogleClient", _FakeClient)
    monkeypatch.setattr(google_collectors, "COLLECTORS", (_Works, _Refused))
    return Settings.from_env()


def test_a_refused_scope_is_not_claimed_as_used(live_settings):
    """Found against a real tenant: Google refused the Policy API scope, and the
    report's methodology page still listed it under "Scopes used"."""
    snapshot = google_collectors.collect(live_settings)

    assert POLICIES not in snapshot.scopes_used
    assert snapshot.scopes_refused == (POLICIES,)
    assert set(live_settings.scopes) <= set(snapshot.scopes_used)


def test_the_collection_window_is_recorded(live_settings):
    before = datetime.now(UTC)
    snapshot = google_collectors.collect(live_settings)
    after = datetime.now(UTC)

    assert snapshot.started_at is not None
    assert before <= snapshot.started_at <= snapshot.collected_at <= after


def test_tool_version_has_one_source():
    assert (
        Snapshot(snapshot_id="s", tenant_id="t", platform="google_workspace").tool_version
        == icp.__version__
    )


def test_a_refused_core_token_stops_the_run_before_anything_is_recorded(monkeypatch):
    """Previously the token was fetched lazily: every collector degraded in turn
    and `collect` wrote an almost empty snapshot as if it had succeeded."""
    from icp.collectors.google.client import GoogleClient

    class _RefusedCredentials:
        def refresh(self, request) -> None:
            raise Exception("('unauthorized_client: Client is unauthorized', {})")

    client = GoogleClient(Settings())
    client._authorize = lambda: _RefusedCredentials()  # type: ignore[method-assign]
    with pytest.raises(CredentialError, match="preflight"):
        client.authenticate()


def test_a_snapshot_from_before_these_fields_still_loads(tmp_path: Path):
    """Your existing snapshots are schema 1.0 and must keep working."""
    from icp.storage.snapshot_store import SnapshotStore

    legacy = {
        "schema_version": "1.0",
        "snapshot_id": "20260101T000000000Z-abcdef12",
        "tenant_id": "dev",
        "platform": "google_workspace",
        "collected_at": "2026-01-01T00:00:00+00:00",
        "tool_version": "0.1.0",
        "scopes_used": ["https://www.googleapis.com/auth/admin.directory.user.readonly"],
        "artifacts": {},
    }
    path = tmp_path / "dev__20260101T000000000Z-abcdef12.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")

    snapshot = SnapshotStore(tmp_path, encrypt=False).load(path)
    assert snapshot.started_at is None
    assert snapshot.scopes_refused == ()
    assert snapshot.partial == {}


def test_the_report_states_the_window_and_the_refused_scope(tenant, result):
    from dataclasses import replace

    from icp.reporting.renderer import ReportRenderer

    tenant = replace(tenant)  # the session fixture is shared; never mutate it
    tenant.snapshot = tenant.snapshot.model_copy(
        update={
            "started_at": datetime(2026, 9, 28, 9, 23, 0, tzinfo=UTC),
            "collected_at": datetime(2026, 9, 28, 9, 23, 33, tzinfo=UTC),
            "scopes_used": ("https://www.googleapis.com/auth/admin.directory.user.readonly",),
            "scopes_refused": (POLICIES,),
        }
    )
    renderer = ReportRenderer()
    context = renderer.build_context(tenant, result, client_name="X", assessor="Y")
    html = renderer.env.get_template("report.html").render(**context)

    assert "Requested but not granted" in html
    assert POLICIES in html
    assert "09:23:00" in html and "09:23:33" in html
