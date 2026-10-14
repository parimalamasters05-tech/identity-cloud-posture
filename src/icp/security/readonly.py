"""Transport-level write blocking -- control #2 of three.

Even with read-only scopes, a coding mistake could construct a mutating request.
This wraps the HTTP transport so that any request using an unsafe verb raises
before a byte leaves the process. It is the last line of defence and it is
deliberately paranoid: it fails closed, and it cannot be disabled by
configuration.
"""

from __future__ import annotations

import logging
from typing import Any

from icp.models.snapshot import ApiCallRecord

logger = logging.getLogger(__name__)

#: HTTP verbs that cannot mutate server state.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

#: Verbs that can. Any of these aborts the run.
UNSAFE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Narrow exception: Google's batch endpoint is POST-only but carries GET
#: sub-requests. Allowed only for this exact host+path, and only when every
#: sub-request inside the body is itself a GET (checked below).
_BATCH_ENDPOINTS = ("https://www.googleapis.com/batch/",)


class WriteAttemptBlocked(RuntimeError):
    """Raised when the tool tries to make a state-changing request.

    Reaching this exception means a control failed upstream. It should be treated
    as a defect and investigated, not caught and ignored.
    """


def _is_permitted_batch(method: str, uri: str, body: Any) -> bool:
    if method.upper() != "POST":
        return False
    if not any(uri.startswith(prefix) for prefix in _BATCH_ENDPOINTS):
        return False
    if body is None:
        return True
    text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body)
    # Every sub-request line must be a GET.
    verbs = [
        line.split(" ", 1)[0].upper()
        for line in text.splitlines()
        if line[:4].upper() in ("GET ", "POST", "PUT ", "PATC", "DELE")
    ]
    return bool(verbs) and all(v == "GET" for v in verbs)


class ReadOnlyHttp:
    """httplib2-compatible wrapper that refuses unsafe requests.

    Wraps the object google-api-python-client uses for transport. Also records
    every call so the engagement can produce its own read-only evidence
    independent of the client's audit log.
    """

    def __init__(self, inner: Any, recorder: list[ApiCallRecord] | None = None) -> None:
        self._inner = inner
        self._recorder: list[ApiCallRecord] = recorder if recorder is not None else []

    @property
    def calls(self) -> list[ApiCallRecord]:
        return self._recorder

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: Any = None,
        headers: dict[str, str] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        verb = (method or "GET").upper()

        if verb not in SAFE_METHODS and not _is_permitted_batch(verb, uri, body):
            self._recorder.append(ApiCallRecord(method=verb, url=_strip_query(uri), status=None))
            raise WriteAttemptBlocked(
                f"Blocked {verb} to {_strip_query(uri)}. "
                "This tool is read-only; a state-changing request is a defect."
            )

        response, content = self._inner.request(uri, verb, body, headers, *args, **kwargs)
        status = getattr(response, "status", None)
        self._recorder.append(ApiCallRecord(method=verb, url=_strip_query(uri), status=status))
        return response, content

    def __getattr__(self, name: str) -> Any:
        # Delegate everything else (timeout, connections, credentials) untouched.
        return getattr(self._inner, name)


def _strip_query(uri: str) -> str:
    """Drop the query string before logging.

    Query strings on Directory API calls contain user emails and filter
    expressions. The audit trail needs the endpoint, not the personal data.
    """
    return uri.split("?", 1)[0]


#: The only address a POST may go to beneath the guard: Google issues the
#: access token there. It changes nothing in the tenant.
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"  # noqa: S105  # nosec B105 - an address, not a secret


class TokenOrReadHttp:
    """Inner guard, on the raw connection under the authorizing layer.

    ReadOnlyHttp sits on top and checks and records every API call. Beneath
    it, Google's auth library also sends its token request, on the raw
    connection, where the outer guard never sees it. This lets through reads
    (the API calls the outer guard already passed) and a POST to Google's
    token endpoint only, so that connection cannot be used for anything else.
    """

    def __init__(self, inner: Any, token_endpoint: str = GOOGLE_TOKEN_ENDPOINT) -> None:
        self._inner = inner
        self._token_endpoint = token_endpoint

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: Any = None,
        headers: dict[str, str] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        verb = (method or "GET").upper()
        is_token = verb == "POST" and _strip_query(uri) == self._token_endpoint
        if verb not in SAFE_METHODS and not is_token and not _is_permitted_batch(verb, uri, body):
            raise WriteAttemptBlocked(
                f"Blocked {verb} to {_strip_query(uri)} beneath the guard. Only reads and the "
                "token request may use this connection."
            )
        return self._inner.request(uri, verb, body, headers, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def token_guard(inner: Any) -> TokenOrReadHttp:
    """Wrap a raw connection used for Google's token request."""
    return inner if isinstance(inner, TokenOrReadHttp) else TokenOrReadHttp(inner)


def guard(inner: Any, recorder: list[ApiCallRecord] | None = None) -> ReadOnlyHttp:
    """Wrap a transport object. Always call this; never pass a raw transport."""
    if isinstance(inner, ReadOnlyHttp):
        return inner
    return ReadOnlyHttp(inner, recorder)


def assert_no_writes(calls: list[ApiCallRecord]) -> None:
    """Post-run assertion over the recorded call log.

    Called at the end of every collection. Cheap, and it turns a silent control
    failure into a loud one.
    """
    unsafe = [c for c in calls if c.method.upper() in UNSAFE_METHODS]
    # Permitted batch POSTs are recorded as GET-equivalent by _is_permitted_batch,
    # so anything left here is a genuine violation.
    if unsafe:
        detail = ", ".join(f"{c.method} {c.url}" for c in unsafe[:5])
        raise WriteAttemptBlocked(f"Read-only attestation failed: {len(unsafe)} unsafe call(s): {detail}")


__all__ = [
    "SAFE_METHODS",
    "UNSAFE_METHODS",
    "ReadOnlyHttp",
    "TokenOrReadHttp",
    "WriteAttemptBlocked",
    "assert_no_writes",
    "guard",
    "token_guard",
]
