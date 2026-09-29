"""Directory groups and their settings-relevant metadata."""

from __future__ import annotations

from typing import Any

from icp.collectors.base import Collector, CollectorClient


class GroupsCollector(Collector):
    name = "google.groups"
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.group.readonly",)

    FIELDS = ("id", "email", "name", "description", "directMembersCount", "adminCreated")

    def collect(self, client: CollectorClient) -> list[dict[str, Any]]:
        service = client.service("admin", "directory_v1")  # type: ignore[attr-defined]
        groups = client.paginate(
            service.groups(),
            "list",
            "groups",
            customer=client.settings.customer_id,  # type: ignore[attr-defined]
            maxResults=client.settings.max_page_size,  # type: ignore[attr-defined]
        )
        return self.project(groups)
