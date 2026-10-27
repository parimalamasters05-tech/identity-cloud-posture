"""The transport guard must block every state-changing verb.

Marked `security`: these tests encode the promise the entire engagement rests
on. If one fails, the tool does not ship, regardless of what else is green.
"""

from __future__ import annotations

import pytest

from icp.models.snapshot import ApiCallRecord
from icp.security.readonly import (
    WriteAttemptBlocked,
    assert_no_writes,
    guard,
)

pytestmark = pytest.mark.security


class FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status


class FakeHttp:
    """Records what actually reached the wire."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    def request(self, uri, method="GET", body=None, headers=None, *args, **kwargs):
        self.seen.append((method, uri))
        return FakeResponse(), b"{}"


@pytest.mark.parametrize("verb", ["POST", "PUT", "PATCH", "DELETE"])
def test_unsafe_verbs_are_blocked(verb):
    inner = FakeHttp()
    http = guard(inner)

    with pytest.raises(WriteAttemptBlocked):
        http.request("https://admin.googleapis.com/admin/directory/v1/users", method=verb)

    assert inner.seen == [], "a blocked request must never reach the transport"


@pytest.mark.parametrize("verb", ["GET", "HEAD", "OPTIONS"])
def test_safe_verbs_pass_through(verb):
    inner = FakeHttp()
    http = guard(inner)
    http.request("https://admin.googleapis.com/admin/directory/v1/users", method=verb)
    assert inner.seen == [(verb, "https://admin.googleapis.com/admin/directory/v1/users")]


def test_lowercase_verb_is_still_blocked():
    """Case normalization matters: httplib2 callers are inconsistent."""
    http = guard(FakeHttp())
    with pytest.raises(WriteAttemptBlocked):
        http.request("https://example.googleapis.com/v1/thing", method="delete")


def test_default_method_is_get():
    inner = FakeHttp()
    guard(inner).request("https://example.googleapis.com/v1/thing")
    assert inner.seen[0][0] == "GET"


@pytest.mark.parametrize(
    "body",
    [
        None,  # the old exemption let a batch POST with no body through
        b"--b\r\nContent-Type: application/http\r\n\r\nGET /admin/directory/v1/users\r\n--b--",
        b"--b\r\nContent-Type: application/http\r\n\r\nDELETE /admin/directory/v1/users/1\r\n--b--",
    ],
    ids=["no body", "only GETs", "a DELETE"],
)
def test_a_batch_post_is_blocked_whatever_it_carries(body):
    """No collector batches, so the batch endpoint has no exemption to abuse."""
    from icp.security.readonly import token_guard

    for http in (guard(FakeHttp()), token_guard(FakeHttp())):
        with pytest.raises(WriteAttemptBlocked):
            http.request("https://www.googleapis.com/batch/admin/directory_v1", method="POST", body=body)
        assert http._inner.seen == []


def test_calls_are_recorded_with_query_strings_stripped():
    """Query strings carry user emails; the audit trail needs endpoints only."""
    recorder: list[ApiCallRecord] = []
    http = guard(FakeHttp(), recorder)
    http.request("https://admin.googleapis.com/v1/users?query=email:alice@corp.example")

    assert len(recorder) == 1
    assert recorder[0].url == "https://admin.googleapis.com/v1/users"
    assert "alice" not in recorder[0].url


def test_blocked_attempt_is_recorded_for_investigation():
    recorder: list[ApiCallRecord] = []
    http = guard(FakeHttp(), recorder)
    with pytest.raises(WriteAttemptBlocked):
        http.request("https://admin.googleapis.com/v1/users", method="DELETE")
    assert recorder[0].method == "DELETE"
    assert recorder[0].status is None


def test_guard_is_idempotent():
    """Double-wrapping would double-record every call."""
    once = guard(FakeHttp())
    assert guard(once) is once


def test_assert_no_writes_passes_on_clean_log():
    assert_no_writes([ApiCallRecord(method="GET", url="https://x/y", status=200)])


def test_assert_no_writes_raises_on_dirty_log():
    with pytest.raises(WriteAttemptBlocked, match="attestation failed"):
        assert_no_writes(
            [
                ApiCallRecord(method="GET", url="https://x/y", status=200),
                ApiCallRecord(method="PATCH", url="https://x/z", status=200),
            ]
        )


def test_unknown_attributes_delegate_to_the_inner_transport():
    """The wrapper must stay drop-in for google-api-python-client."""

    class WithTimeout(FakeHttp):
        timeout = 42

    assert guard(WithTimeout()).timeout == 42
