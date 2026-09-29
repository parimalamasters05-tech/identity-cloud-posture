"""External sharing and public exposure settings.

Deliberately limited to *settings and metadata*. This collector never lists file
contents and never reads a document. Where Drive file metadata is collected, it
is restricted to files whose permissions already make them public -- the
smallest set that supports the finding.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from icp.collectors.base import Collector, CollectorClient, CollectorError
from icp.models.enums import Assessability

logger = logging.getLogger(__name__)

#: Same concurrency as the per-user OAuth enumeration, for the same reason:
#: fast enough for the five-minute budget, gentle enough on per-user limits.
_MAX_WORKERS = 8


class DriveSettingsCollector(Collector):
    name = "google.drive_settings"
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.domain.readonly",)

    def collect(self, client: CollectorClient) -> dict[str, Any]:
        # Drive sharing policy lives in the Admin console, exposed through the
        # Admin Settings API, whose availability varies. Degrade rather than fail.
        try:
            service = client.service("admin", "directory_v1")  # type: ignore[attr-defined]
            domains = client.paginate(
                service.domains(),
                "list",
                "domains",
                customer=client.settings.customer_id,  # type: ignore[attr-defined]
            )
        except Exception as exc:
            raise CollectorError(
                f"Domain settings unavailable: {exc}", Assessability.NOT_ASSESSABLE_PERMISSION
            ) from exc

        return {
            "domains": [
                {
                    "domainName": d.get("domainName"),
                    "isPrimary": d.get("isPrimary"),
                    "verified": d.get("verified"),
                }
                for d in domains
            ]
        }


class PublicDriveItemsCollector(Collector):
    """Files and folders shared to 'anyone with the link' or 'anyone on the web'.

    Requires drive.metadata.readonly with domain-wide delegation: names, owners
    and sharing settings, with no ability to read file content at all. Only that
    metadata is retained -- never a download URL.

    Drive returns only what the signed-in account can see, and that is as true
    of a super-admin as of anyone. The first version searched as the admin
    subject alone and found only the admin's own files: on the dev tenant a
    public file owned by another user was simply absent, while the report said
    "Drive files and folders that anyone with the link can open". So:

      * each active user's Drive is searched *as that user*, for files they own;
      * the admin subject's search also covers shared drives it belongs to;
      * suspended and archived users cannot be signed in as, so their files
        are not searched -- and the report names them rather than implying
        they were checked.
    """

    name = "google.public_drive_items"
    required_scopes = (
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        # Fallback for accounts that cannot be searched: the Drive audit log.
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    )

    FIELDS = ("id", "name", "mimeType", "owners", "shared", "webViewLink", "modifiedTime")

    _PUBLIC = "(visibility='anyoneWithLink' or visibility='anyoneCanFind')"
    _FILE_FIELDS = "nextPageToken, files(id,name,mimeType,shared,modifiedTime,owners(emailAddress))"

    def collect(self, client: CollectorClient) -> list[dict[str, Any]]:
        users = getattr(client, "known_users", None) or []
        active = [
            u for u in users if not u.get("suspended") and not u.get("archived") and u.get("primaryEmail")
        ]
        inactive = [u["primaryEmail"] for u in users if u not in active and u.get("primaryEmail")]
        page_size = min(client.settings.max_page_size, 100)  # type: ignore[attr-defined]

        # Shared drives (and the admin's own files), as the admin subject.
        service = client.service("drive", "v3")  # type: ignore[attr-defined]
        found = client.paginate(  # type: ignore[attr-defined]
            service.files(),
            "list",
            "files",
            q=self._PUBLIC,
            fields=self._FILE_FIELDS,
            pageSize=page_size,
            corpora="allDrives",
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
        )

        def search(user: dict[str, Any]) -> tuple[str, list[dict[str, Any]] | None, str | None]:
            email = user["primaryEmail"]
            try:
                # Built inside the worker: one transport per thread (see client).
                as_user = client.service("drive", "v3", subject=email)  # type: ignore[attr-defined]
                items = client.paginate(  # type: ignore[attr-defined]
                    as_user.files(),
                    "list",
                    "files",
                    q=f"'me' in owners and {self._PUBLIC}",
                    fields=self._FILE_FIELDS,
                    pageSize=page_size,
                    corpora="user",
                )
                return email, items, None
            except Exception as exc:
                return email, None, f"{type(exc).__name__}: {exc}"

        failed: list[str] = []
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for email, items, error in pool.map(search, active):
                if error is not None:
                    logger.warning("Drive search as %s failed: %s", email, error)
                    failed.append(email)
                else:
                    found.extend(items or [])

        note = getattr(client, "note_incomplete", None)
        if not users and note:
            note(
                "The staff list was not available, so only the assessment account's own files "
                "and shared drives were searched. Public files owned by staff were not checked."
            )

        # One file can be seen by several searches (the admin's and its owner's).
        unique = {item["id"]: item for item in found if item.get("id")}
        projected = self.project(sorted(unique.values(), key=lambda i: (i.get("name") or "", i["id"])))
        for item in projected:
            owners = item.get("owners") or []
            item["owners"] = [o.get("emailAddress") for o in owners if isinstance(o, dict)]
            item["source"] = "drive_search"
            item.pop("webViewLink", None)  # a link to client data; not ours to store

        # Accounts whose Drive could not be searched -- suspended or archived
        # (Google will not act as them) or whose search failed. Their public
        # files are recovered from the Drive audit log instead.
        not_searched = sorted(failed) + sorted(inactive)
        if not_searched:
            from_log, log_error = _made_public_per_audit_log(client, not_searched)
            known = {item["id"] for item in projected}
            projected.extend(item for item in from_log if item["id"] not in known)
            if note:
                if log_error is None:
                    note(
                        "Some accounts' Drive could not be searched directly ("
                        + _reasons(failed, inactive)
                        + f"). Their files made public in the last {AUDIT_WINDOW_DAYS} days were "
                        "found from Google's Drive audit log instead; files they made public "
                        "before that could not be checked and may still be open to anyone with the link."
                    )
                else:
                    note(
                        "Public files owned by some accounts were not checked ("
                        + _reasons(failed, inactive)
                        + "), and Google's Drive audit log could not be read as a fallback. Files "
                        "those accounts shared publicly can still be open to anyone with the link."
                    )
        return projected


#: Google keeps Drive audit events for about six months.
AUDIT_WINDOW_DAYS = 180
#: Visibility values Google's Drive audit log uses for "anyone, no sign-in".
#: "people_within_domain_with_link" is organization-only and deliberately absent.
_PUBLIC_VISIBILITY = frozenset({"people_with_link", "public_on_the_web"})


def _reasons(failed: list[str], inactive: list[str]) -> str:
    parts = []
    if inactive:
        parts.append(f"suspended or archived: {', '.join(sorted(inactive))}")
    if failed:
        parts.append(f"search failed: {', '.join(sorted(failed))}")
    return "; ".join(parts)


def _made_public_per_audit_log(
    client: CollectorClient, owners: list[str]
) -> tuple[list[dict[str, Any]], str | None]:
    """Files owned by `owners` whose latest recorded visibility change made them public.

    Read-only: one paginated Reports API listing of visibility-change events.
    The latest event per file wins, so a file made public and later made
    private again is not reported.
    """
    from datetime import UTC, datetime, timedelta

    wanted = {o.lower() for o in owners}
    try:
        service = client.service("admin", "reports_v1")  # type: ignore[attr-defined]
        events = client.paginate(  # type: ignore[attr-defined]
            service.activities(),
            "list",
            "items",
            max_pages=20,
            userKey="all",
            applicationName="drive",
            eventName="change_document_visibility",
            startTime=(datetime.now(UTC) - timedelta(days=AUDIT_WINDOW_DAYS)).isoformat(),
            maxResults=1000,
        )
    except Exception as exc:
        logger.warning("Drive audit log unavailable: %s", exc)
        return [], f"{type(exc).__name__}: {exc}"

    latest: dict[str, tuple[str, dict[str, Any]]] = {}
    for item in events:
        when = str((item.get("id") or {}).get("time") or "")
        for event in item.get("events") or []:
            params = {p.get("name"): p.get("value") for p in event.get("parameters") or []}
            doc_id = params.get("doc_id")
            if doc_id and (doc_id not in latest or when > latest[doc_id][0]):
                latest[doc_id] = (when, params)

    found = []
    for doc_id, (when, params) in sorted(latest.items()):
        owner = str(params.get("owner") or "").lower()
        if owner in wanted and params.get("visibility") in _PUBLIC_VISIBILITY:
            found.append(
                {
                    "id": doc_id,
                    "name": params.get("doc_title") or "(untitled)",
                    "mimeType": params.get("doc_type"),
                    "owners": [owner],
                    "shared": True,
                    "modifiedTime": when,
                    "source": "audit_log",
                    "made_public_at": when,
                }
            )
    return found, None
