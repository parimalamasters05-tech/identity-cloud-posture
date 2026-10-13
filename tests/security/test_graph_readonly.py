"""The Microsoft Graph guard: read-only, one token request, never file content."""

from __future__ import annotations

import base64
import io
import json
import urllib.error

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from icp.security.graph_readonly import (
    GraphCredentials,
    GraphReadOnly,
    check_request,
    client_assertion,
)
from icp.security.readonly import WriteAttemptBlocked

TENANT = "00000000-0000-0000-0000-000000000001"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
GRAPH = "https://graph.microsoft.com/v1.0"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def creds(key):
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return GraphCredentials(
        tenant_id=TENANT, client_id="client-1", thumbprint="AB" * 20, private_key_pem=pem
    )


# -- the refusal rules ---------------------------------------------------------


@pytest.mark.parametrize("verb", ["POST", "PUT", "PATCH", "DELETE"])
def test_no_write_verb_reaches_graph(verb):
    with pytest.raises(WriteAttemptBlocked):
        check_request(verb, f"{GRAPH}/users/abc", token_url=TOKEN_URL)


def test_the_only_post_is_this_tenants_token_request():
    check_request("POST", TOKEN_URL, token_url=TOKEN_URL)  # allowed
    other = TOKEN_URL.replace(TENANT, "11111111-1111-1111-1111-111111111111")
    with pytest.raises(WriteAttemptBlocked):
        check_request("POST", other, token_url=TOKEN_URL)
    with pytest.raises(WriteAttemptBlocked):
        check_request(
            "POST", "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode", token_url=TOKEN_URL
        )


@pytest.mark.parametrize(
    "path",
    [
        "drives/d1/items/i1/content",
        "users/u1/drive/root:/Board papers.docx:/content",
        "sites/s1/drive/items/i1/Content",
        "users/u1/messages/m1/$value",
        "users/u1/photo/$value",
    ],
)
def test_file_content_is_never_fetched(path):
    """Sites.Read.All could read documents; the guard makes sure it never does."""
    with pytest.raises(WriteAttemptBlocked, match="content"):
        check_request("GET", f"{GRAPH}/{path}", token_url=TOKEN_URL)


def test_sharing_metadata_is_allowed():
    check_request("GET", f"{GRAPH}/drives/d1/items/i1/permissions", token_url=TOKEN_URL)
    check_request(
        "GET", f"{GRAPH}/users/u1/drive/root/children?$select=id,name,shared", token_url=TOKEN_URL
    )


@pytest.mark.parametrize(
    "url", ["https://evil.example/v1.0/users", "http://graph.microsoft.com/v1.0/users"]
)
def test_other_hosts_and_plain_http_are_refused(url):
    with pytest.raises(WriteAttemptBlocked):
        check_request("GET", url, token_url=TOKEN_URL)


# -- the certificate sign-in ---------------------------------------------------


def _decode(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_client_assertion_is_signed_by_the_certificate_key(creds, key):
    token = client_assertion(creds, now=1_000_000)
    header, claims, signature = token.split(".")
    assert _decode(header)["alg"] == "RS256"
    assert base64.urlsafe_b64decode(_decode(header)["x5t"] + "=") == bytes.fromhex("AB" * 20)
    body = _decode(claims)
    assert body["aud"] == TOKEN_URL and body["iss"] == body["sub"] == "client-1"
    assert body["exp"] - body["nbf"] == 600
    key.public_key().verify(
        base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
        f"{header}.{claims}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


# -- the client ----------------------------------------------------------------


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeMicrosoft:
    def __init__(self, pages):
        self.pages = list(pages)
        self.requests: list[tuple[str, str]] = []

    def __call__(self, request, timeout=None):
        self.requests.append((request.get_method(), request.full_url))
        if request.full_url == TOKEN_URL:
            return _Response(json.dumps({"access_token": "t", "expires_in": 3600}).encode())
        return _Response(json.dumps(self.pages.pop(0)).encode())


def test_reads_are_recorded_and_the_token_request_is_counted_apart(creds):
    fake = _FakeMicrosoft([{"value": [{"id": "1"}]}, {"value": [{"id": "2"}]}])
    client = GraphReadOnly(creds, opener=fake)
    client.get("users", {"$top": "1"})
    client.get("groups")

    assert [m for m, _ in fake.requests] == ["POST", "GET", "GET"]  # token fetched once, then reused
    assert client.auth_requests == 1
    assert {c.method for c in client.calls} == {"GET"}
    assert all("?" not in c.url for c in client.calls)  # query strings are not logged


def test_pagination_follows_next_links_but_only_to_graph(creds):
    fake = _FakeMicrosoft(
        [
            {"value": [{"id": "1"}], "@odata.nextLink": f"{GRAPH}/users?$skiptoken=x"},
            {"value": [{"id": "2"}], "@odata.nextLink": "https://evil.example/v1.0/users?$skiptoken=y"},
        ]
    )
    client = GraphReadOnly(creds, opener=fake)
    with pytest.raises(WriteAttemptBlocked, match="unexpected host"):
        client.paginate("users")
    assert len(client.calls) == 2


def test_microsofts_error_code_is_kept(creds):
    def refuse(request, timeout=None):
        if request.full_url == TOKEN_URL:
            return _Response(json.dumps({"access_token": "t", "expires_in": 3600}).encode())
        body = json.dumps(
            {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
        )
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(body.encode()))

    from icp.security.graph_readonly import GraphError

    client = GraphReadOnly(creds, opener=refuse)
    with pytest.raises(GraphError) as caught:
        client.get("auditLogs/signIns")
    assert caught.value.status == 403 and caught.value.code == "Authorization_RequestDenied"
    assert client.calls[-1].status == 403


# -- slow and busy responses (found live, 13 Oct 2026) -----------------------------


class _Flaky:
    """Fails the first `failures` Graph requests with `error`, then answers."""

    def __init__(self, error, failures):
        self.error, self.failures, self.graph_requests = error, failures, 0

    def __call__(self, request, timeout=None):
        if request.full_url == TOKEN_URL:
            return _Response(json.dumps({"access_token": "t", "expires_in": 3600}).encode())
        self.graph_requests += 1
        if self.graph_requests <= self.failures:
            raise self.error() if callable(self.error) else self.error
        return _Response(json.dumps({"value": [{"id": "1"}]}).encode())


def _throttled():
    return urllib.error.HTTPError(
        f"{GRAPH}/users", 429, "Too Many Requests", {"Retry-After": "7"}, io.BytesIO(b"{}")
    )


def test_a_timeout_is_retried_and_the_read_then_succeeds(creds):
    """One slow response raised TimeoutError, nothing caught it, and a whole
    live collection died on its last collector."""
    pauses: list[float] = []
    fake = _Flaky(TimeoutError("The read operation timed out"), failures=2)
    client = GraphReadOnly(creds, opener=fake, sleep=pauses.append)

    assert client.get("auditLogs/signIns") == {"value": [{"id": "1"}]}
    assert fake.graph_requests == 3 and client.retries == 2
    assert pauses == [1.0, 2.0]  # backs off between attempts
    assert [c.status for c in client.calls] == [200]


def test_no_response_after_every_attempt_is_a_graph_error_not_a_crash(creds):
    from icp.security.graph_readonly import GraphError

    client = GraphReadOnly(
        creds, opener=_Flaky(TimeoutError("timed out"), failures=99), sleep=lambda _s: None
    )
    with pytest.raises(GraphError) as caught:
        client.get("auditLogs/signIns")
    assert caught.value.status is None and caught.value.code == "no_response"
    assert client.calls[-1].status is None


def test_throttling_waits_as_long_as_microsoft_asks(creds):
    pauses: list[float] = []
    client = GraphReadOnly(creds, opener=_Flaky(_throttled, failures=1), sleep=pauses.append)
    client.get("users")
    assert pauses == [7.0]


def test_a_refusal_is_not_retried(creds):
    from icp.security.graph_readonly import GraphError

    def forbidden():
        return urllib.error.HTTPError(f"{GRAPH}/users", 403, "Forbidden", {}, io.BytesIO(b"{}"))

    fake = _Flaky(forbidden, failures=99)
    client = GraphReadOnly(creds, opener=fake, sleep=lambda _s: None)
    with pytest.raises(GraphError):
        client.get("users")
    assert fake.graph_requests == 1 and client.retries == 0
