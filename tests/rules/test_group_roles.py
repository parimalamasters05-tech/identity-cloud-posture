"""Administrators who hold a role through a group are administrators.

Review finding (27 Oct 2026): both platforms skipped role assignments made to
a group, so its members were invisible to the admin-sprawl, dormant-admin and
administrator second-step checks.
"""

from __future__ import annotations

from copy import deepcopy

from tests.rules.test_m365_rules import _artifacts, _run

from icp.collectors import microsoft as m365
from icp.normalizers.google import normalize

SUPER_ADMIN_ROLE = "10001"  # the fixture's super-admin role
ALEX = "100000000000000000010"  # an ordinary fixture user


def _google(snapshot, members):
    artifacts = deepcopy(snapshot.artifacts)
    artifacts["google.role_assignments"] = [
        *artifacts["google.role_assignments"],
        {
            "roleAssignmentId": "ra-g",
            "roleId": SUPER_ADMIN_ROLE,
            "assignedTo": "grp-1",
            "assigneeType": "group",
        },
    ]
    if members is not None:
        artifacts["google.role_group_members"] = {"grp-1": members}
    return normalize(snapshot.model_copy(update={"artifacts": artifacts}))


def _super_admins(tenant):
    return {u.id for u in tenant.users if u.is_super_admin}


def test_google_a_super_admin_role_held_through_a_group_reaches_its_members(snapshot):
    before = _super_admins(normalize(snapshot))
    assert ALEX not in before
    tenant = _google(snapshot, {"users": [ALEX], "everyone": False})
    assert _super_admins(tenant) == before | {ALEX}


def test_google_a_group_of_everyone_makes_everyone_hold_the_role(snapshot):
    tenant = _google(snapshot, {"users": [], "everyone": True})
    assert _super_admins(tenant) == {u.id for u in tenant.users}


def test_google_snapshots_without_group_members_read_as_before(snapshot):
    assert _super_admins(_google(snapshot, None)) == _super_admins(normalize(snapshot))


def _m365_with_group_admins():
    artifacts = deepcopy(_artifacts())
    artifacts["m365.roles"]["assignments"].append({"principalId": "g-admins", "roleDefinitionId": "r-ga"})
    artifacts["m365.roles"]["group_members"] = {"g-admins": ["u-owen", "u-staff1"]}
    return artifacts


def test_m365_a_global_admin_role_held_through_a_group_reaches_its_members():
    _, _, before = _run()
    tenant, _, after = _run(_m365_with_group_admins())
    admins = {u.id for u in tenant.users if u.is_super_admin}
    assert {"u-owen", "u-staff1"} <= admins
    # Both have a password only: they are now named as administrators without a second step.
    named = {e.id for f in after["M365-MFA-001"] for e in f.affected_entities}
    assert {"u-owen", "u-staff1"} <= named
    assert after["M365-ADM-001"][0].entity_count == before["M365-ADM-001"][0].entity_count + 2


class _Graph:
    def __init__(self, routes):
        self.routes, self.requested = routes, []

    def get(self, path, params=None):
        return {}

    def paginate(self, path, params=None, **_):
        self.requested.append((path, (params or {}).get("$filter")))
        answer = self.routes[path]
        if isinstance(answer, Exception):
            raise answer
        return answer


def _graph(members):
    return _Graph(
        {
            "roleManagement/directory/roleDefinitions": [
                {"id": "r-ga", "displayName": "Global Administrator"}
            ],
            "roleManagement/directory/roleAssignments": [
                {"principalId": "u-1", "roleDefinitionId": "r-ga"},
                {"principalId": "g-1", "roleDefinitionId": "r-ga"},
            ],
            # g-2 is role-assignable but holds no role: its members are not read.
            "groups": [{"id": "g-1"}, {"id": "g-2"}],
            "groups/g-1/members": members,
        }
    )


def test_m365_collector_reads_members_only_of_groups_holding_a_role():
    graph = _graph([{"id": "u-2", "@odata.type": "#microsoft.graph.user"}])
    roles = m365._roles(graph, {"partial": {}})
    assert roles["group_members"] == {"g-1": ["u-2"]}
    assert ("groups", "isAssignableToRole eq true") in graph.requested
    assert all(path != "groups/g-2/members" for path, _ in graph.requested)


def test_m365_unreadable_group_members_are_partial_coverage_not_a_lost_role_list():
    from icp.security.graph_readonly import GraphError

    ctx = {"partial": {}}
    roles = m365._roles(_graph(GraphError(403, "Authorization_RequestDenied", "x")), ctx)
    assert roles["assignments"] and roles["group_members"] == {}
    assert "g-1 (Authorization_RequestDenied)" in ctx["partial"]["m365.roles"]


def test_the_group_members_endpoint_is_reviewed():
    from icp.security.graph_readonly import check_request

    check_request(
        "GET",
        "https://graph.microsoft.com/v1.0/groups/0f6c1e2a-0000-4000-8000-000000000003/members?$select=id",
        token_url="https://login.microsoftonline.com/t/oauth2/v2.0/token",
    )


# -- GWS-MFA-004: enrolled by choice, not enforced (review, 27 Oct 2026) -----------


def _enforcement(snapshot, change):
    from icp.rules import assess

    users = [change(dict(u)) for u in snapshot.artifacts["google.users"]]
    tenant = normalize(
        snapshot.model_copy(update={"artifacts": {**snapshot.artifacts, "google.users": users}})
    )
    return [f for f in assess(tenant).findings if f.rule_id == "GWS-MFA-004"]


def test_enrolled_but_not_enforced_accounts_are_reported(snapshot):
    [finding] = _enforcement(snapshot, lambda u: {**u, "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": False})
    active = sum(
        1 for u in snapshot.artifacts["google.users"] if not u.get("suspended") and not u.get("archived")
    )
    assert finding.entity_count == active
    assert finding.remediation_key == "mfa.enforce_all_users"  # one action with GWS-MFA-002


def test_enforced_accounts_and_unenrolled_accounts_are_not_reported_here(snapshot):
    assert _enforcement(snapshot, lambda u: {**u, "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": True}) == []
    # Not enrolled at all: GWS-MFA-001 and GWS-MFA-002 report those.
    assert _enforcement(snapshot, lambda u: {**u, "isEnrolledIn2Sv": False, "isEnforcedIn2Sv": False}) == []
