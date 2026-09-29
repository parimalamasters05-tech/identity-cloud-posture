"""When each application was authorized, revoked and last used, per user.

The Directory API's token listing says which grants exist, not when they were
made or whether they are used. That lives in the Reports API's token audit log.
This collector reads it once and keeps only a per (application, user) summary:
dates, never IP addresses, and never the raw events.

What the log contains varies by tenant. On the dev tenant it held consent
(`authorize`) and `revoke` events only -- no record of applications actually
using their access. `activity_recorded` says whether any usage event was seen,
so the dormancy check can report "not assessed" instead of calling every app
dormant for want of data.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from icp.collectors.base import Collector, CollectorClient

#: Google retains token audit events for about six months.
WINDOW_DAYS = 180
#: 50 pages x 1000 events. Usage events can be far more numerous than the
#: directory; a truncated read is recorded as partial and narrows the window the
#: dormancy check may rely on, rather than blowing the collection budget.
MAX_PAGES = 50

#: Event names that change a grant rather than use it.
_GRANT_EVENTS = frozenset({"authorize", "revoke"})


class TokenActivityCollector(Collector):
    name = "google.token_activity"
    required_scopes = ("https://www.googleapis.com/auth/admin.reports.audit.readonly",)

    def collect(self, client: CollectorClient) -> dict[str, Any]:
        service = client.service("admin", "reports_v1")  # type: ignore[attr-defined]
        now = datetime.now(UTC)
        start = now - timedelta(days=WINDOW_DAYS)

        truncations = getattr(client, "truncations", [])
        before = len(truncations)
        items = client.paginate(  # type: ignore[attr-defined]
            service.activities(),
            "list",
            "items",
            max_pages=MAX_PAGES,
            userKey="all",
            applicationName="token",
            startTime=start.isoformat(),
            maxResults=1000,
        )
        return summarize(items, window_start=start, truncated=len(truncations) > before)


def summarize(items: list[dict[str, Any]], *, window_start: datetime, truncated: bool) -> dict[str, Any]:
    """Reduce raw token audit events to per (client, user) dates."""
    records: dict[tuple[str, str], dict[str, Any]] = {}
    event_names: dict[str, int] = {}
    times: list[str] = []

    for item in items:
        when = (item.get("id") or {}).get("time")
        user = str((item.get("actor") or {}).get("email") or "").lower()
        if when:
            times.append(when)
        for event in item.get("events") or []:
            name = str(event.get("name") or "")
            event_names[name] = event_names.get(name, 0) + 1
            params = _params(event)
            client_id = params.get("client_id")
            if not client_id or not user or not when:
                continue

            record = records.setdefault(
                (client_id, user),
                {
                    "client_id": client_id,
                    "app_name": params.get("app_name"),
                    "user": user,
                    "last_authorized": None,
                    "last_revoked": None,
                    "last_activity": None,
                },
            )
            field = {"authorize": "last_authorized", "revoke": "last_revoked"}.get(name, "last_activity")
            if record[field] is None or when > record[field]:
                record[field] = when

    return {
        "window_days": WINDOW_DAYS,
        "window_start": window_start.isoformat(),
        "events_read": len(items),
        "oldest_event": min(times) if times else None,
        "newest_event": max(times) if times else None,
        "truncated": truncated,
        "event_names": dict(sorted(event_names.items())),
        "activity_recorded": any(n not in _GRANT_EVENTS for n in event_names),
        "apps": sorted(records.values(), key=lambda r: (r["client_id"], r["user"])),
    }


def _params(event: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for param in event.get("parameters") or []:
        if "value" in param:
            out[str(param.get("name"))] = str(param["value"])
    return out
