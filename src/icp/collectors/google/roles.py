"""Admin roles and role assignments.

Two artifacts, because a role assignment on its own is meaningless: the
assignment names a roleId, and the role definition says whether that role is
super-admin and which privileges it carries.
"""

from __future__ import annotations

from typing import Any

from icp.collectors.base import Collector, CollectorClient


class RolesCollector(Collector):
    name = "google.roles"
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",)

    FIELDS = ("roleId", "roleName", "roleDescription", "isSuperAdminRole", "isSystemRole", "rolePrivileges")

    def collect(self, client: CollectorClient) -> list[dict[str, Any]]:
        service = client.service("admin", "directory_v1")  # type: ignore[attr-defined]
        roles = client.paginate(
            service.roles(),
            "list",
            "items",
            customer=client.settings.customer_id,  # type: ignore[attr-defined]
        )
        return self.project(roles)


class RoleAssignmentsCollector(Collector):
    name = "google.role_assignments"
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",)

    FIELDS = ("roleAssignmentId", "roleId", "assignedTo", "scopeType", "orgUnitId", "assigneeType")

    def collect(self, client: CollectorClient) -> list[dict[str, Any]]:
        service = client.service("admin", "directory_v1")  # type: ignore[attr-defined]
        assignments = client.paginate(
            service.roleAssignments(),
            "list",
            "items",
            customer=client.settings.customer_id,  # type: ignore[attr-defined]
            maxResults=client.settings.max_page_size,  # type: ignore[attr-defined]
        )
        return self.project(assignments)
