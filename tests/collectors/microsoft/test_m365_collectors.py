"""Microsoft 365 collectors, against Graph response shapes seen on the dev tenant.

Each test pins a behaviour found live on day one (6 Oct 2026) or a data
minimization rule: what must never reach the snapshot.
"""

from __future__ import annotations

from typing import Any

import pytest

from icp.collectors import microsoft as m365
from icp.models.enums import Assessability, Platform
from icp.security.graph_readonly import GraphError


class FakeGraph:
    """Answers by path prefix; raises GraphError for paths mapped to one."""

    def __init__(self, routes: dict[str, Any]):
        self.routes = routes
        self.calls: list[Any] = []
        self.auth_requests = 1
        self.requested: list[str] = []

    def _answer(self, path: str) -> Any:
        self.requested.append(path)
        for prefix, answer in self.routes.items():
            if path == prefix or path.startswith(prefix):
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise GraphError(404, "Request_ResourceNotFound", f"no route for {path}")

    def get(self, path: str, params: dict | None = None) -> dict:
        return self._answer(path)

    def paginate(self, path: str, params: dict | None = None, *, max_pages: int | None = None) -> list:
        return list(self._answer(path).get("value", []))


DANA = {
    "id": "u-dana",
    "userPrincipalName": "dana@lab.example",
    "userType": "Member",
    "accountEnabled": True,
    "assignedLicenses": [{"skuId": "x"}],
}
NINA = {**DANA, "id": "u-nina", "userPrincipalName": "nina@lab.example", "accountEnabled": False}
GUEST = {**DANA, "id": "u-guest", "userPrincipalName": "p_ext#EXT#@lab.example", "userType": "Guest"}
UNLICENSED = {**DANA, "id": "u-svc", "userPrincipalName": "svc@lab.example", "assignedLicenses": []}


def _ctx(*users):
    return {
        "users": [
            m365._keep(u, m365.USER_FIELDS) | {"assignedLicenses": len(u["assignedLicenses"])}
            for u in users
        ],
        "partial": {},
    }


# -- public files ----------------------------------------------------------------


def _drive(items):
    return {"value": items}


def test_public_files_use_delta_and_find_anyone_links_including_a_blocked_owner():
    """`search` returned HTTP 500 app-only on the live tenant; `delta` works,
    and app-only access reaches a blocked user's OneDrive."""
    shared = {
        "id": "i1",
        "name": "TEST board papers.docx",
        "shared": {},
        "file": {},
        "parentReference": {"driveId": "d1"},
    }
    graph = FakeGraph(
        {
            "users/u-dana/drive/root/delta": _drive(
                [shared, {"id": "i2", "name": "private.docx", "file": {}}]
            ),
            "users/u-nina/drive/root/delta": _drive(
                [{**shared, "id": "i3", "name": "departed.docx", "parentReference": {"driveId": "d2"}}]
            ),
            "drives/d1/items/i1/permissions": {"value": [{"link": {"scope": "anonymous"}}]},
            "drives/d2/items/i3/permissions": {
                "value": [{"link": {"scope": "anonymous"}}, {"link": {"scope": "organization"}}]
            },
        }
    )
    found = m365._public_files(graph, _ctx(DANA, NINA))
    assert {(f["name"], f["owner_enabled"]) for f in found} == {
        ("TEST board papers.docx", True),
        ("departed.docx", False),
    }
    assert not any("search" in p for p in graph.requested)


def test_organization_only_links_and_deleted_items_are_not_public():
    graph = FakeGraph(
        {
            "users/u-dana/drive/root/delta": _drive(
                [
                    {"id": "i1", "name": "org.docx", "shared": {}, "parentReference": {"driveId": "d1"}},
                    {
                        "id": "i9",
                        "name": "gone.docx",
                        "shared": {},
                        "deleted": {},
                        "parentReference": {"driveId": "d1"},
                    },
                ]
            ),
            "drives/d1/items/i1/permissions": {"value": [{"link": {"scope": "organization"}}]},
        }
    )
    assert m365._public_files(graph, _ctx(DANA)) == []
    assert "drives/d1/items/i9/permissions" not in graph.requested


def test_guests_and_unlicensed_accounts_are_not_searched_and_a_missing_drive_is_quiet():
    graph = FakeGraph({})  # dana's drive 404s: never signed in, not provisioned
    ctx = _ctx(DANA, GUEST, UNLICENSED)
    assert m365._public_files(graph, ctx) == []
    assert graph.requested == ["users/u-dana/drive/root/delta"]
    assert "m365.public_files" not in ctx["partial"]


def test_a_drive_that_errors_is_named_as_partial_coverage():
    graph = FakeGraph({"users/u-dana/drive/root/delta": GraphError(500, "generalException", "x")})
    ctx = _ctx(DANA)
    m365._public_files(graph, ctx)
    assert "dana@lab.example (generalException)" in ctx["partial"]["m365.public_files"]


# -- data minimization -------------------------------------------------------------


def test_sign_in_methods_keep_the_type_never_the_phone_number():
    graph = FakeGraph(
        {
            "users/u-dana/authentication/methods": {
                "value": [
                    {
                        "@odata.type": "#microsoft.graph.phoneAuthenticationMethod",
                        "phoneNumber": "+1 555 0100",
                        "phoneType": "mobile",
                    },
                    {
                        "@odata.type": "#microsoft.graph.fido2AuthenticationMethod",
                        "model": "YubiKey 5",
                        "createdDateTime": "2026-10-06T10:00:00Z",
                    },
                ]
            }
        }
    )
    out = m365._auth_methods(graph, _ctx(DANA))
    assert out["entries"]["u-dana"] == [
        {"type": "phoneAuthenticationMethod", "created": None},
        {"type": "fido2AuthenticationMethod", "created": "2026-10-06T10:00:00Z"},
    ]
    assert "555" not in str(out)


def test_app_secrets_keep_dates_never_the_hint():
    graph = FakeGraph(
        {
            "applications": {
                "value": [
                    {
                        "id": "a1",
                        "displayName": "Backup Sync Test",
                        "passwordCredentials": [
                            {
                                "keyId": "k",
                                "hint": "Qx7",
                                "endDateTime": "2028-10-05T00:00:00Z",
                                "secretText": None,
                            }
                        ],
                        "keyCredentials": [],
                    }
                ]
            }
        }
    )
    [app] = m365._applications(graph, {"partial": {}})
    assert app["secrets"] == [{"keyId": "k", "endDateTime": "2028-10-05T00:00:00Z"}]
    assert "Qx7" not in str(app)


def test_users_keep_a_licence_count_not_the_licence_list():
    graph = FakeGraph({"users": {"value": [{**DANA, "mail": "x", "mobilePhone": "+1"}]}})
    [user] = m365._users(graph, {"partial": {}})
    assert user["assignedLicenses"] == 1
    assert "mobilePhone" not in user


def test_graph_permission_ids_are_named_from_graphs_own_catalogue():
    graph = FakeGraph(
        {
            "servicePrincipals/g/appRoleAssignedTo": {
                "value": [
                    {
                        "principalId": "sp1",
                        "principalDisplayName": "Backup Sync Test",
                        "appRoleId": "r-mail",
                        "principalType": "ServicePrincipal",
                    }
                ]
            },
            "servicePrincipals/g/delegatedPermissionClassifications": {
                "value": [{"permissionName": "Mail.Read", "classification": "low"}]
            },
            "servicePrincipals": {
                "value": [{"id": "g", "appRoles": [{"id": "r-mail", "value": "Mail.Read"}]}]
            },
            "oauth2PermissionGrants": {
                "value": [
                    {
                        "clientId": "sp2",
                        "consentType": "Principal",
                        "principalId": "u-nina",
                        "scope": " Mail.Read",
                    }
                ]
            },
        }
    )
    out = m365._graph_permissions(graph, {"partial": {}})
    assert out["application_grants"][0]["permission"] == "Mail.Read"
    assert out["low_impact_classifications"] == [{"permissionName": "Mail.Read", "classification": "low"}]


# -- the run -----------------------------------------------------------------------


def test_sign_in_and_audit_logs_are_filtered_on_their_own_timestamp_fields():
    """A 400 on day one: sign-in logs use createdDateTime, not activityDateTime."""
    seen: dict[str, dict] = {}

    class Recording(FakeGraph):
        def get(self, path, params=None):
            seen[path] = params or {}
            return {"value": []}

    m365._audit_readiness(Recording({}), {"partial": {}})
    assert seen["auditLogs/signIns"]["$filter"].startswith("createdDateTime ge ")
    assert seen["auditLogs/directoryAudits"]["$filter"].startswith("activityDateTime ge ")


def test_a_failing_collector_degrades_alone_and_the_snapshot_is_microsoft(monkeypatch):
    def boom(c, ctx):
        raise GraphError(403, "Authorization_RequestDenied", "Insufficient privileges")

    ok = lambda c, ctx: {"fine": True}  # noqa: E731
    monkeypatch.setattr(m365, "COLLECTORS", (("m365.policies", boom), ("m365.organization", ok)))
    snapshot = m365.collect(FakeGraph({}), tenant_id="m365")

    assert snapshot.platform == Platform.MICROSOFT_365
    assert snapshot.artifacts == {"m365.organization": {"fine": True}}
    [error] = snapshot.errors
    assert error.collector == "m365.policies"
    assert error.assessability == Assessability.NOT_ASSESSABLE_PERMISSION


def test_a_recorded_write_aborts_the_run(monkeypatch):
    from icp.models.snapshot import ApiCallRecord

    graph = FakeGraph({})
    graph.calls.append(ApiCallRecord(method="PATCH", url="https://graph.microsoft.com/v1.0/users/x"))
    monkeypatch.setattr(m365, "COLLECTORS", ())
    with pytest.raises(RuntimeError, match="Read-only violation"):
        m365.collect(graph, tenant_id="m365")
