"""Directory users.

Field projection here is the single most important data-minimization decision in
the project: the Directory API will happily return addresses, phone numbers,
employee IDs, and custom schemas. None of that is needed to assess posture, so
none of it is collected.
"""

from __future__ import annotations

from typing import Any

from icp.collectors.base import Collector, CollectorClient


class UsersCollector(Collector):
    name = "google.users"
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.user.readonly",)

    FIELDS = (
        "id",
        "primaryEmail",
        "name.fullName",
        "suspended",
        "archived",
        "isAdmin",
        "isDelegatedAdmin",
        "isEnrolledIn2Sv",
        "isEnforcedIn2Sv",
        "creationTime",
        "lastLoginTime",
        "orgUnitPath",
        "agreedToTerms",
        "changePasswordAtNextLogin",
    )

    def collect(self, client: CollectorClient) -> list[dict[str, Any]]:
        service = client.service("admin", "directory_v1")  # type: ignore[attr-defined]
        users = client.paginate(
            service.users(),
            "list",
            "users",
            customer=client.settings.customer_id,  # type: ignore[attr-defined]
            maxResults=client.settings.max_page_size,  # type: ignore[attr-defined]
            projection="full",
            orderBy="email",
        )
        return self.project(users)
