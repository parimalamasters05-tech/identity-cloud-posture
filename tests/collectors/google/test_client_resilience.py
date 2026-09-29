"""Retries, backoff and pagination, against a fake Google.

None of this was tested before: the behaviour that decides whether a busy or
flaky tenant yields a complete assessment, a partial one, or a crashed run.
"""

from __future__ import annotations

import httplib2
import pytest
from googleapiclient.errors import HttpError

from icp.collectors.google.client import GoogleClient
from icp.config import Settings
from icp.security.readonly import WriteAttemptBlocked


def _http_error(status: int, reason: str = "", retry_after: str | None = None) -> HttpError:
    headers = {"status": str(status)}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    body = f'{{"error": {{"errors": [{{"reason": "{reason}"}}]}}}}'.encode()
    return HttpError(httplib2.Response(headers), body)


class _Request:
    """Plays back a script: an exception to raise, or a response to return."""

    def __init__(self, script: list) -> None:
        self.script = script
        self.executions = 0

    def execute(self, num_retries: int = 0):
        assert num_retries == 0, "retries belong to the client, not the library"
        step = self.script[min(self.executions, len(self.script) - 1)]
        self.executions += 1
        if isinstance(step, BaseException):
            raise step
        return step


@pytest.fixture
def client() -> GoogleClient:
    c = GoogleClient(Settings(max_retries=5))
    c.slept = []  # type: ignore[attr-defined]
    c._sleep = c.slept.append  # type: ignore[attr-defined,method-assign]
    return c


# -- backoff -------------------------------------------------------------------


def test_rate_limit_is_retried_until_it_clears(client):
    request = _Request([_http_error(429), _http_error(429), {"ok": True}])
    assert client._execute(request) == {"ok": True}
    assert request.executions == 3
    assert len(client.slept) == 2


def test_retry_after_header_is_honoured(client):
    request = _Request([_http_error(429, retry_after="7"), {"ok": True}])
    client._execute(request)
    assert client.slept == [7.0]


def test_rate_limit_403_is_retried_but_a_permission_403_is_not(client):
    limited = _Request([_http_error(403, "userRateLimitExceeded"), {"ok": True}])
    assert client._execute(limited) == {"ok": True}

    denied = _Request([_http_error(403, "forbidden")])
    with pytest.raises(HttpError):
        client._execute(denied)
    assert denied.executions == 1, "a missing permission must fail fast, not wait ~30s"


@pytest.mark.parametrize(
    "blip",
    [ConnectionResetError("reset"), TimeoutError("timed out"), httplib2.ServerNotFoundError("dns")],
)
def test_network_blips_are_retried(client, blip):
    """Previously a single timeout degraded the whole collector."""
    request = _Request([blip, {"ok": True}])
    assert client._execute(request) == {"ok": True}
    assert request.executions == 2


def test_a_persistent_network_failure_gives_up_after_max_retries(client):
    request = _Request([TimeoutError("timed out")])
    with pytest.raises(TimeoutError):
        client._execute(request)
    assert request.executions == 5
    assert all(0 <= s <= 32 for s in client.slept)


@pytest.mark.security
def test_a_blocked_write_is_never_retried(client):
    request = _Request([WriteAttemptBlocked("POST blocked")])
    with pytest.raises(WriteAttemptBlocked):
        client._execute(request)
    assert request.executions == 1
    assert client.slept == []


# -- pagination ----------------------------------------------------------------


class _Pages:
    """A list method that serves pages; `total=None` never ends."""

    def __init__(self, total: int | None) -> None:
        self.total = total
        self.tokens_seen: list[str | None] = []

    def list(self, **params):
        token = params.get("pageToken")
        self.tokens_seen.append(token)
        page = int(token) if token else 0
        body = {"items": [{"n": page}]}
        if self.total is None or page + 1 < self.total:
            body["nextPageToken"] = str(page + 1)
        return _Request([body])


def test_every_page_is_followed(client):
    resource = _Pages(total=3)
    items = client.paginate(resource, "list", "items", maxResults=1)
    assert [i["n"] for i in items] == [0, 1, 2]
    assert resource.tokens_seen == [None, "1", "2"]
    assert client.truncations == []


def test_the_page_cap_is_recorded_not_just_logged(client):
    """Truncated data used to look complete in the report."""
    client.max_pages = 3
    items = client.paginate(_Pages(total=None), "list", "items")
    assert len(items) == 3
    assert len(client.truncations) == 1
    assert "incomplete" in client.truncations[0]
