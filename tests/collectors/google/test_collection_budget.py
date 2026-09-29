"""The five-minute collection budget, checked offline.

The only collection step that grows with headcount one call at a time is the
OAuth collector: Google's token listing is per user and not batchable. Every
other collector is a handful of paginated calls. So the budget holds if (a) the
users listing pages at the maximum size and (b) the per-user token calls really
run concurrently. Both are tested here against a simulated tenant with real
per-call latency, through the real `paginate` / `_execute` / thread pool.

Projection: at a pessimistic 0.5s per Google call, the per-user fan-out for a
1,000-person organization is 1000 / 8 workers * 0.5s = ~63s, plus ~40 fixed
calls (~20s) -- well inside 300s. Measured on the dev tenant: 13s for 33 calls.
`icp collect` prints each run's duration against the budget.
"""

from __future__ import annotations

import threading
import time

import pytest

from icp.collectors.google import COLLECTION_BUDGET_SECONDS
from icp.collectors.google.client import GoogleClient
from icp.collectors.google.oauth import _MAX_WORKERS, OAuthTokensCollector
from icp.collectors.google.users import UsersCollector
from icp.config import Settings

USERS = 400
LATENCY = 0.02  # seconds per simulated API call


class _Request:
    def __init__(self, payload: dict, counter: list[int], lock: threading.Lock) -> None:
        self._payload, self._counter, self._lock = payload, counter, lock

    def execute(self, num_retries: int = 0) -> dict:
        time.sleep(LATENCY)
        with self._lock:
            self._counter[0] += 1
        return self._payload


class _Tenant:
    """Just enough of the Directory API: users.list (paged) and tokens.list."""

    def __init__(self) -> None:
        self.calls = [0]
        self.lock = threading.Lock()
        self.users = [
            {"id": f"{i:021d}", "primaryEmail": f"u{i}@scale.example", "isAdmin": False}
            for i in range(USERS)
        ]
        self.page_sizes: list[int] = []

    def users_list(self, *, maxResults: int, pageToken: str | None = None, **_: object) -> _Request:
        start = int(pageToken or 0)
        page = self.users[start : start + maxResults]
        self.page_sizes.append(maxResults)
        payload: dict = {"users": page}
        if start + maxResults < len(self.users):
            payload["nextPageToken"] = str(start + maxResults)
        return _Request(payload, self.calls, self.lock)

    def tokens_list(self, *, userKey: str) -> _Request:
        grant = {"clientId": "1.apps.googleusercontent.com", "displayText": "App", "scopes": ["openid"]}
        return _Request({"items": [grant]}, self.calls, self.lock)


class _Resource:
    def __init__(self, **methods) -> None:
        for name, method in methods.items():
            setattr(self, name, method)


class _ScaleClient(GoogleClient):
    def __init__(self, settings: Settings, tenant: _Tenant) -> None:
        super().__init__(settings)
        self._tenant = tenant
        self._sleep = lambda _s: None

    def service(self, api: str, version: str, *, optional_scopes: tuple[str, ...] = ()) -> _Resource:
        t = self._tenant
        return _Resource(
            users=lambda: _Resource(list=t.users_list),
            tokens=lambda: _Resource(list=t.tokens_list),
        )


@pytest.fixture
def scale_run():
    tenant = _Tenant()
    client = _ScaleClient(Settings(), tenant)

    started = time.monotonic()
    users = UsersCollector().collect(client)
    client.known_users = users  # type: ignore[attr-defined]
    tokens = OAuthTokensCollector().collect(client)
    return tenant, users, tokens, time.monotonic() - started


def test_every_user_and_grant_is_collected(scale_run):
    _, users, tokens, _ = scale_run
    assert len(users) == USERS
    assert len(tokens["grants"]) == USERS
    assert tokens["failed_users"] == []


def test_users_are_listed_at_the_maximum_page_size(scale_run):
    tenant, *_ = scale_run
    assert set(tenant.page_sizes) == {Settings().max_page_size}


def test_per_user_calls_run_concurrently(scale_run):
    """Serial would be USERS * LATENCY = 8s. Allow generous CI scheduling slack,
    but fail if concurrency is lost."""
    tenant, _, _, elapsed = scale_run
    serial = tenant.calls[0] * LATENCY
    assert elapsed < serial / (_MAX_WORKERS / 2), f"{elapsed:.1f}s against {serial:.1f}s serial"


def test_the_budget_is_the_briefs_five_minutes():
    assert COLLECTION_BUDGET_SECONDS == 300
