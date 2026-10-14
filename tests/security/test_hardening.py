"""Security hardening found by the full audit (14 Oct 2026), locked in.

Each test names the gap it closes:
  * Google's token request went out on a raw connection beneath the guard;
  * urllib followed redirects that Graph's guard never saw;
  * the third-party Prowler container received the whole .env, including the
    snapshot encryption key;
  * CI actions were pinned by tag, which their owners can move.
"""

from __future__ import annotations

import re

import pytest
import yaml
from tests.conftest import REPO_ROOT

from icp.security.graph_readonly import _OPENER, GraphError, _RefuseRedirects
from icp.security.readonly import GOOGLE_TOKEN_ENDPOINT, TokenOrReadHttp, WriteAttemptBlocked, token_guard


class _Raw:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def request(self, uri, method="GET", body=None, headers=None, *args, **kwargs):
        self.sent.append((method, uri))
        return {"status": 200}, b"{}"


# -- Google: beneath the guard -------------------------------------------------------------


def test_the_raw_google_connection_allows_reads_and_the_token_request_only():
    raw = _Raw()
    http = token_guard(raw)
    http.request("https://admin.googleapis.com/admin/directory/v1/users", "GET")
    http.request(GOOGLE_TOKEN_ENDPOINT, "POST", body=b"grant_type=...")
    assert [m for m, _ in raw.sent] == ["GET", "POST"]


@pytest.mark.parametrize(
    ("method", "uri"),
    [
        ("POST", "https://admin.googleapis.com/admin/directory/v1/users"),
        ("POST", "https://oauth2.googleapis.com/revoke"),
        ("POST", "https://evil.example/token"),
        ("DELETE", "https://admin.googleapis.com/admin/directory/v1/users/x/tokens/y"),
        ("PATCH", GOOGLE_TOKEN_ENDPOINT),
        ("PUT", "https://www.googleapis.com/drive/v3/files/x"),
    ],
)
def test_anything_else_on_the_raw_google_connection_is_blocked(method, uri):
    raw = _Raw()
    with pytest.raises(WriteAttemptBlocked):
        TokenOrReadHttp(raw).request(uri, method)
    assert raw.sent == []  # refused before a byte left


def test_the_google_client_puts_the_inner_guard_on_every_raw_connection():
    """Source check: both raw connections (token at start-up, and beneath the
    authorizing layer for each service) are wrapped."""
    client = (REPO_ROOT / "src" / "icp" / "collectors" / "google" / "client.py").read_text("utf-8")
    preflight = (REPO_ROOT / "src" / "icp" / "preflight.py").read_text("utf-8")
    for source in (client, preflight):
        raw = re.findall(r"httplib2\.Http\(", source)
        wrapped = re.findall(r"token_guard\(httplib2\.Http\(", source)
        assert raw and len(raw) == len(wrapped), "a raw Google connection is not guarded"


# -- Microsoft: redirects ------------------------------------------------------------------


def test_graph_redirects_are_refused_not_followed():
    """Graph answers a file-content request with a redirect to a download host."""
    with pytest.raises(GraphError) as caught:
        _RefuseRedirects().redirect_request(
            None, None, 302, "Found", {}, "https://tenant.sharepoint.com/_layouts/download.aspx?x=1"
        )
    assert caught.value.code == "redirect_refused"
    assert any(isinstance(h, _RefuseRedirects) for h in _OPENER.handlers)


# -- Containers ----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text("utf-8"))["services"]


def test_prowler_gets_the_three_aws_values_and_nothing_else_from_env(compose):
    prowler = compose["prowler"]
    assert "env_file" not in prowler, (
        "the whole .env (with ICP_SNAPSHOT_KEY) would reach a third-party image"
    )
    assert set(prowler["environment"]) == {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_DEFAULT_REGION",
    }


def test_prowler_runs_pinned_and_locked_down(compose):
    prowler = compose["prowler"]
    assert re.search(r"@sha256:[0-9a-f]{64}$", prowler["image"]), "pin the third-party image by digest"
    assert prowler["read_only"] is True
    assert prowler["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in prowler["security_opt"]


def test_every_service_of_this_tool_is_locked_down(compose):
    ours = {name: s for name, s in compose.items() if s.get("image") == "icp:local"}
    assert ours, "no services found"
    for name, service in ours.items():
        assert service.get("read_only") is True, name
        assert service.get("cap_drop") == ["ALL"], name
        assert "no-new-privileges:true" in service.get("security_opt", []), name


def test_services_that_need_no_network_have_none(compose):
    for name in ("demo", "collect-aws"):
        assert compose[name].get("network_mode") == "none", name


# -- CI -----------------------------------------------------------------------------------


def test_every_ci_action_is_pinned_to_a_commit():
    """A tag can be moved by the action's owner; a commit cannot."""
    workflows = list((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    uses = [u for w in workflows for u in re.findall(r"uses:\s*(\S+)", w.read_text("utf-8"))]
    assert uses
    unpinned = [u for u in uses if not re.search(r"@[0-9a-f]{40}$", u)]
    assert unpinned == []
