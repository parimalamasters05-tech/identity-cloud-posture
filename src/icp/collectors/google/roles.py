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


class RoleGroupMembersCollector(Collector):
    """Who holds an administrator role through a group.

    A role can be assigned to a group; everyone in it then holds the role.
    Without this, such administrators were invisible to every admin check.
    One members listing per group that holds a role (usually none or one),
    with indirect members included so nested groups are covered. IDs and
    member types only -- no addresses.
    """

    name = "google.role_group_members"
    required_scopes = (
        "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
    )

    FIELDS = ("id", "type")

    def collect(self, client: CollectorClient) -> dict[str, dict[str, Any]]:
        service = client.service("admin", "directory_v1")  # type: ignore[attr-defined]
        assignments = client.paginate(
            service.roleAssignments(),
            "list",
            "items",
            customer=client.settings.customer_id,  # type: ignore[attr-defined]
            maxResults=client.settings.max_page_size,  # type: ignore[attr-defined]
        )
        groups = sorted(
            {
                str(a.get("assignedTo"))
                for a in assignments
                if str(a.get("assigneeType", "")).lower() == "group"
            }
        )
        out: dict[str, dict[str, Any]] = {}
        for group in groups:
            members = self.project(
                client.paginate(
                    service.members(), "list", "members", groupKey=group, includeDerivedMembership=True
                )
            )
            out[group] = {
                "users": sorted({str(m["id"]) for m in members if m.get("type") == "USER" and m.get("id")}),
                # A CUSTOMER member is "everyone in the organization".
                "everyone": any(m.get("type") == "CUSTOMER" for m in members),
            }
        return out


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
