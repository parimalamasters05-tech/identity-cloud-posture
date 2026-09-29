"""Audit and logging readiness.

The question this collector supports is narrow and important: if something went
wrong last month, could this organization reconstruct it? That means checking
that admin and login audit streams exist and are populated -- not reading their
contents in bulk.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from icp.collectors.base import Collector, CollectorClient

#: Only a probe window; we are testing for presence, not harvesting activity.
_PROBE_DAYS = 30
_PROBE_LIMIT = 50


class AuditReadinessCollector(Collector):
    name = "google.audit_readiness"
    required_scopes = ("https://www.googleapis.com/auth/admin.reports.audit.readonly",)

    def collect(self, client: CollectorClient) -> dict[str, Any]:
        service = client.service("admin", "reports_v1")  # type: ignore[attr-defined]
        start = (datetime.now(UTC) - timedelta(days=_PROBE_DAYS)).isoformat()

        applications = ("admin", "login", "token", "drive")
        results: dict[str, Any] = {"probe_window_days": _PROBE_DAYS, "streams": {}}

        for app in applications:
            try:
                response = client.call(
                    service.activities(),
                    "list",
                    userKey="all",
                    applicationName=app,
                    startTime=start,
                    maxResults=_PROBE_LIMIT,
                )
                items = response.get("items", []) or []
                results["streams"][app] = {
                    "available": True,
                    "event_count_sampled": len(items),
                    "oldest_sampled": items[-1].get("id", {}).get("time") if items else None,
                    "newest_sampled": items[0].get("id", {}).get("time") if items else None,
                }
            except Exception as exc:
                status = getattr(getattr(exc, "resp", None), "status", None)
                results["streams"][app] = {
                    "available": False,
                    "http_status": status,
                    "reason": type(exc).__name__,
                }

        return results
