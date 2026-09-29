"""Collector behaviour that does not need a tenant.

Live API behaviour is not unit-tested; that is what the dev tenant is for. What
is tested here is the part that has to be right regardless of what Google
returns: projection, degradation, and ordering.
"""

from __future__ import annotations

import pytest

from icp.collectors.base import CollectorError, to_collection_error
from icp.collectors.google import COLLECTORS
from icp.collectors.google.mfa import _flatten
from icp.collectors.google.users import UsersCollector
from icp.models.enums import Assessability


class FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status


class FakeHttpError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.resp = FakeResponse(status)


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, Assessability.NOT_ASSESSABLE_PERMISSION),
        (403, Assessability.NOT_ASSESSABLE_PERMISSION),
        (404, Assessability.NOT_ASSESSABLE_LICENSE),
        (500, Assessability.NOT_ASSESSABLE_ERROR),
    ],
)
def test_http_errors_map_to_the_right_degradation(status, expected):
    """A 403 is a permission problem; a 404 is usually a licence tier.

    Telling those apart matters, because one is the client's setup mistake and
    the other is not their fault at all.
    """
    error = to_collection_error("google.mfa", FakeHttpError(status))
    assert error.assessability == expected
    assert error.http_status == status


def test_permission_error_names_the_likely_cause():
    error = to_collection_error("google.mfa", FakeHttpError(403))
    assert "domain-wide delegation" in error.message


def test_collector_error_passes_its_own_assessability_through():
    error = to_collection_error(
        "google.mfa", CollectorError("no report", Assessability.NOT_ASSESSABLE_LICENSE)
    )
    assert error.assessability == Assessability.NOT_ASSESSABLE_LICENSE
    assert "no report" in error.message


def test_users_collector_runs_first():
    """The OAuth collector enumerates tokens per user and needs that list."""
    assert COLLECTORS[0] is UsersCollector


def test_every_collector_declares_a_name_and_scopes():
    for collector_cls in COLLECTORS:
        collector = collector_cls()
        assert collector.name, f"{collector_cls.__name__} has no artifact name"
        assert collector.name.startswith("google.")
        assert collector.required_scopes, f"{collector_cls.__name__} declares no scopes"


def test_collector_names_are_unique():
    names = [c().name for c in COLLECTORS]
    assert len(names) == len(set(names))


def test_mfa_report_flattening():
    """Google nests usage parameters in a list of name/value dicts."""
    flattened = _flatten(
        [
            {
                "entity": {"profileId": "1", "userEmail": "a@b.example"},
                # Google's real field names, as returned by a live tenant.
                "parameters": [
                    {"name": "accounts:num_security_keys", "intValue": "2"},
                    {"name": "accounts:num_passkeys_enrolled", "intValue": "1"},
                ],
            }
        ]
    )
    assert flattened == [
        {
            "profile_id": "1",
            "email": "a@b.example",
            "num_security_keys": "2",
            "num_passkeys_enrolled": "1",
        }
    ]


def test_projection_is_stable_for_missing_fields():
    """A tenant that omits an optional field must not produce a ragged snapshot."""
    projected = UsersCollector().project([{"id": "1"}])
    assert projected == [{"id": "1"}]


def test_missing_credentials_is_fatal_not_nine_degraded_collectors(monkeypatch, tmp_path):
    """A credential failure must stop the run, not quietly empty the snapshot.

    Graceful degradation exists for a missing permission on one API surface.
    Having no usable credential at all is a setup error, and letting it degrade
    every collector in turn produces a snapshot with zero artifacts that reads
    like a tenant problem instead of a configuration one.
    """
    from icp.collectors import google as google_collectors
    from icp.config import Settings
    from icp.security.credentials import CredentialError

    monkeypatch.setenv("ICP_TENANT_ID", "dev")
    monkeypatch.setenv("ICP_GOOGLE_ADMIN_SUBJECT", "icp-assessment@dev.example")
    monkeypatch.setenv("ICP_GOOGLE_PRIMARY_DOMAIN", "dev.example")
    monkeypatch.delenv("ICP_GOOGLE_KEY_FILE", raising=False)
    monkeypatch.delenv("ICP_GOOGLE_SA_KEY_JSON", raising=False)

    with pytest.raises(CredentialError, match="No Google credential configured"):
        google_collectors.collect(Settings.from_env())


def test_service_objects_are_not_shared_between_threads():
    """httplib2 is not thread-safe, and sharing one corrupts the heap.

    Observed against a real tenant as `free(): invalid next size (normal)` --
    a glibc abort, not a Python exception, so the process dies with no
    traceback. The OAuth collector runs eight workers, which makes this the
    single most dangerous concurrency bug in the project.
    """
    import threading

    from icp.collectors.google.client import GoogleClient
    from icp.config import Settings

    client = GoogleClient(Settings())
    built: list[object] = []
    errors: list[Exception] = []
    collect_lock = threading.Lock()

    # Stub the expensive parts; we are testing caching scope, not Google.
    def fake_build(api, version, http=None, **kwargs):
        return object()

    client._authorize = lambda: object()  # type: ignore[method-assign]

    import googleapiclient.discovery as discovery

    original = discovery.build
    discovery.build = fake_build
    try:
        ready = threading.Barrier(4)

        def worker() -> None:
            try:
                # Hold all four threads alive simultaneously. Without the
                # barrier they run sequentially, thread IDs get recycled,
                # and the test can pass against shared state.
                ready.wait(timeout=5)
                service = client.service("admin", "directory_v1")
                with collect_lock:
                    built.append(service)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        discovery.build = original

    assert not errors, errors
    assert len(built) == 4
    assert len({id(s) for s in built}) == 4, "service objects were shared across threads"


def test_oauth_collector_never_uses_a_service_from_another_thread():
    """A per-thread client cache is useless if the collector shares its result.

    Observed against a real tenant as `corrupted size vs. prev_size`: the
    collector built one service on the calling thread and handed it to all
    eight workers, bypassing the thread-local cache entirely.
    """
    import threading

    from icp.collectors.google.oauth import OAuthTokensCollector

    violations: list[str] = []

    class FakeService:
        def __init__(self) -> None:
            self.owner = threading.get_ident()

        def tokens(self) -> FakeService:
            if threading.get_ident() != self.owner:
                violations.append("service used outside the thread that built it")
            return self

    class FakeClient:
        def __init__(self) -> None:
            self.known_users = [{"id": str(i), "primaryEmail": f"u{i}@dev.example"} for i in range(32)]
            self._local = threading.local()

        def service(self, api: str, version: str) -> FakeService:
            if not hasattr(self._local, "svc"):
                self._local.svc = FakeService()
            return self._local.svc

        def call(self, resource, method, **kwargs):
            return {"items": [{"clientId": "c", "scopes": [], "userKey": kwargs["userKey"]}]}

    result = OAuthTokensCollector().collect(FakeClient())

    assert not violations, violations[0]
    assert result["users_enumerated"] == 32
    assert not result["failed_users"]


def test_the_call_log_is_shared_so_attestation_covers_every_thread():
    """Per-thread transports must still record into one log.

    The read-only attestation is worthless if a worker thread's calls are
    invisible to it.
    """
    import threading

    from icp.collectors.google.client import _LockedRecorder
    from icp.models.snapshot import ApiCallRecord

    backing: list[ApiCallRecord] = []
    lock = threading.Lock()

    def worker() -> None:
        recorder = _LockedRecorder(backing, lock)
        for _ in range(50):
            recorder.append(ApiCallRecord(method="GET", url="https://x/y", status=200))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(backing) == 400, "calls were lost between threads"


def test_mfa_collector_declares_the_usage_scope_not_the_audit_scope():
    """Activities and usage reports are different surfaces with different scopes.

    Found against a real tenant: the activities probe passed and the MFA
    collector still returned 403 insufficientPermissions.
    """
    from icp.collectors.google.mfa import MfaCollector

    assert MfaCollector.required_scopes == ("https://www.googleapis.com/auth/admin.reports.usage.readonly",)
