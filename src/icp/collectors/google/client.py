"""Google Admin SDK client.

Responsibilities: build the API service behind the read-only transport guard,
paginate, back off on rate limits, and record every call. Nothing else -- no
business logic lives here.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any

from icp.config import Settings
from icp.models.snapshot import ApiCallRecord
from icp.security.credentials import load_google_credentials
from icp.security.readonly import WriteAttemptBlocked, assert_no_writes, guard
from icp.security.scopes import assert_read_only

logger = logging.getLogger(__name__)

#: Google returns these when we are going too fast. Everything else is fatal.
_RETRYABLE_STATUS = frozenset({403, 429, 500, 502, 503, 504})
_RETRYABLE_REASONS = frozenset(
    {"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "backendError", "internalError"}
)


class GoogleClient:
    """Thin wrapper over google-api-python-client discovery services."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.calls: list[ApiCallRecord] = []
        self._credentials = None
        self._credentials_lock = threading.Lock()
        self._call_lock = threading.Lock()
        self._sleep = time.sleep

        #: Hard cap per paginated listing; see `paginate`.
        self.max_pages = 500
        #: Listings cut short by `max_pages`, as report-ready messages.
        self.truncations: list[str] = []

        # httplib2 is not thread-safe, and neither is a discovery service built
        # on top of one. Sharing a single transport across the OAuth collector's
        # worker threads corrupts the heap -- observed as
        # `free(): invalid next size` mid-collection, which is a glibc abort
        # rather than a Python exception, so it takes the whole process down
        # with no traceback. Each thread therefore gets its own transport and
        # its own service objects, sharing only the credentials.
        self._local = threading.local()

    # -- construction -----------------------------------------------------------

    def _authorize(self) -> Any:
        """Load credentials once, under a lock.

        Credential construction is cheap but not reentrant, and the OAuth
        collector calls this from several threads at once.
        """
        with self._credentials_lock:
            if self._credentials is None:
                assert_read_only(list(self.settings.scopes))
                self._credentials, source = load_google_credentials(
                    subject=self.settings.admin_subject,
                    scopes=self.settings.scopes,
                    key_file=self.settings.google_key_file,
                )
                logger.info("Authorized via %s", source.kind)
            return self._credentials

    def authenticate(self) -> None:
        """Load credentials up front, before any collector runs.

        Without this, a missing or malformed key fails inside the first API call
        of every collector in turn -- so the run "succeeds" with nine degraded
        collectors and writes an empty snapshot. Graceful degradation is for a
        missing permission on one surface. Having no usable credential at all is
        a fatal configuration error and must look like one.

        The token is fetched here, not lazily. Google refuses the whole token if
        any core scope is missing from the delegation entry, and a lazy fetch
        turned that into nine degraded collectors and an almost empty snapshot.
        """
        import google_auth_httplib2
        import httplib2

        from icp.security.credentials import CredentialError

        credentials = self._authorize()
        try:
            credentials.refresh(
                google_auth_httplib2.Request(httplib2.Http(timeout=self.settings.request_timeout_seconds))
            )
        except Exception as exc:
            if "unauthorized_client" in str(exc):
                raise CredentialError(
                    "Google refused a token for the required scopes (unauthorized_client): at "
                    "least one is missing from the domain-wide delegation entry, or the entry's "
                    "client ID is wrong. Run `icp preflight` to see exactly which."
                ) from exc
            raise CredentialError(f"Could not obtain a Google token: {type(exc).__name__}: {exc}") from exc

    def service(
        self,
        api: str,
        version: str,
        *,
        optional_scopes: tuple[str, ...] = (),
        subject: str | None = None,
    ) -> Any:
        """Build (and cache per thread) a discovery service behind the write guard.

        Cached on thread-local storage, never on the instance. Two threads
        sharing one httplib2 connection is a memory-safety bug, not merely a
        race: it shows up as a glibc abort mid-collection with no traceback.

        `optional_scopes` gives this service a token of its own for those scopes
        only, so a client who has not delegated them loses this one collector
        rather than every collector.

        `subject` acts as that user instead of the admin subject. Drive only
        returns files the signed-in account can see -- a super-admin included --
        so finding staff's public files means asking as each of them. Same
        scopes, same write guard, same call log.
        """
        services = getattr(self._local, "services", None)
        if services is None:
            services = self._local.services = {}

        key = (api, version, optional_scopes, subject)
        if key in services:
            return services[key]

        import google_auth_httplib2
        import httplib2
        from googleapiclient.discovery import build  # imported lazily; heavy

        credentials = self._authorize()
        if optional_scopes:
            undeclared = set(optional_scopes) - set(self.settings.optional_scopes)
            if undeclared:
                raise ValueError(f"Not declared as optional scopes: {sorted(undeclared)}")
            assert_read_only(list(optional_scopes))
            credentials = credentials.with_scopes(list(optional_scopes))
        if subject:
            credentials = credentials.with_subject(subject)

        base_http = httplib2.Http(timeout=self.settings.request_timeout_seconds)
        authorized = google_auth_httplib2.AuthorizedHttp(credentials, http=base_http)

        # Every request from here on passes through the guard. The recorder is
        # shared deliberately -- the read-only attestation must cover every
        # thread -- and its appends are serialized.
        http = guard(authorized, _LockedRecorder(self.calls, self._call_lock))

        service = build(api, version, http=http, cache_discovery=False)
        services[key] = service
        return service

    # -- request execution ------------------------------------------------------

    def _execute(self, request: Any) -> dict[str, Any]:
        """Execute with bounded exponential backoff and full jitter.

        Retried: rate limits, server errors, and network failures (timeouts,
        resets, DNS) -- all transient, and every request here is a GET, so a
        retry cannot duplicate an effect. Never retried: a blocked write, a
        refused token, or any other client error.
        """
        import httplib2
        from googleapiclient.errors import HttpError

        delay = 1.0
        last_error: Exception | None = None

        for attempt in range(1, self.settings.max_retries + 1):
            try:
                return request.execute(num_retries=0)
            except WriteAttemptBlocked:
                raise
            except HttpError as exc:
                status = getattr(exc.resp, "status", None)
                reason = _extract_reason(exc)
                retryable = status in _RETRYABLE_STATUS and (status != 403 or reason in _RETRYABLE_REASONS)
                if not retryable or attempt == self.settings.max_retries:
                    raise
                last_error = exc
                wait = _retry_after(exc)
                label = f"status={status} reason={reason}"
            except (OSError, httplib2.HttpLib2Error) as exc:
                if attempt == self.settings.max_retries:
                    raise
                last_error = exc
                wait = None
                label = f"network error {type(exc).__name__}"

            # Retry jitter, not a security decision -- `random` is correct here.
            sleep_for = wait if wait is not None else random.uniform(0, min(delay, 32.0))  # noqa: S311
            logger.warning(
                "Retryable failure (%s), attempt %d/%d, sleeping %.1fs",
                label,
                attempt,
                self.settings.max_retries,
                sleep_for,
            )
            self._sleep(sleep_for)
            delay *= 2

        raise RuntimeError("Retry loop exhausted") from last_error

    def call(self, resource: Any, method: str, **kwargs: Any) -> dict[str, Any]:
        """Single non-paginated call."""
        return self._execute(getattr(resource, method)(**kwargs))

    def paginate(
        self, resource: Any, method: str, key: str, *, max_pages: int | None = None, **kwargs: Any
    ) -> list[dict[str, Any]]:
        """Follow `nextPageToken` to exhaustion, returning the flattened list.

        A hard page cap guards against a pathological tenant or an API change
        turning a collection run into an unbounded loop. `max_pages` lowers it
        for listings that can be far larger than the directory, like audit logs.
        """
        items: list[dict[str, Any]] = []
        page_token: str | None = None
        pages = 0
        cap = min(max_pages or self.max_pages, self.max_pages)

        while True:
            params = dict(kwargs)
            if page_token:
                params["pageToken"] = page_token
            response = self._execute(getattr(resource, method)(**params))
            items.extend(response.get(key, []) or [])

            page_token = response.get("nextPageToken")
            pages += 1
            if not page_token:
                break
            if pages >= cap:
                # Recorded, not just logged: the collector's data is incomplete,
                # and the report must say so rather than read as complete.
                message = (
                    f"Stopped after {cap} pages ({len(items)} {key}); more existed. "
                    "Results in this area are incomplete."
                )
                logger.warning("Pagination cap hit for %s.%s: %s", method, key, message)
                with self._call_lock:
                    self.truncations.append(message)
                break

        return items

    def note_incomplete(self, message: str) -> None:
        """Record that the running collector's data is incomplete, and why.

        Goes into the snapshot's `partial` record for that collector, which the
        report turns into a "partly assessed" coverage note -- the same path a
        truncated listing takes.
        """
        with self._call_lock:
            self.truncations.append(message)

    # -- attestation ------------------------------------------------------------

    def attest_read_only(self) -> None:
        """Assert no unsafe call was recorded. Called at the end of every run."""
        assert_no_writes(self.calls)


def _retry_after(exc: Any) -> float | None:
    """Honour Google's Retry-After header when it sends one, within reason."""
    try:
        value = float(exc.resp.get("retry-after"))
    except (AttributeError, TypeError, ValueError):
        return None
    return min(max(value, 0.0), 60.0)


def _extract_reason(exc: Any) -> str:
    """Pull Google's machine-readable error reason out of the response body."""
    try:
        import json

        payload = json.loads(exc.content.decode("utf-8"))
        return str(payload["error"]["errors"][0].get("reason", ""))
    except Exception:
        return ""


class _LockedRecorder(list):
    """The shared API-call log, safe to append from worker threads.

    `list.append` is atomic under CPython's GIL, but the read-only attestation
    depends on this log being complete and the project should not rest a
    security control on an interpreter implementation detail.
    """

    def __init__(self, backing: list[ApiCallRecord], lock: threading.Lock) -> None:
        super().__init__()
        self._backing = backing
        self._lock = lock

    def append(self, record: ApiCallRecord) -> None:  # type: ignore[override]
        with self._lock:
            self._backing.append(record)
