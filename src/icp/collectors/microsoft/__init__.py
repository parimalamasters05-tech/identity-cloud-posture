"""Microsoft 365 collectors (week 5), read-only through Microsoft Graph.

Same contract as the Google side: every collector writes one artifact into
the snapshot, a failing collector degrades its own checks with a recorded
reason and never stops the run, and nothing downstream talks to Microsoft.

Data minimization is done here, at the boundary: `$select` asks only for the
fields a check reads, and `_keep` drops anything sensitive that Graph returns
anyway (phone numbers on sign-in methods, client-secret hints). File contents
are never requested; the transport guard refuses content URLs outright.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from icp.models.enums import Assessability, Platform
from icp.models.snapshot import CollectionError, Snapshot
from icp.security.graph_readonly import GraphError, GraphReadOnly

logger = logging.getLogger(__name__)

#: Microsoft Graph's own service principal (the "resource" of every Graph permission).
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

#: The Graph application permissions this tool holds, recorded in the snapshot
#: the way Google scopes are. Verified live by `icp preflight-m365`.
PERMISSIONS_USED: tuple[str, ...] = (
    "Application.Read.All",
    "AuditLog.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.Directory",
    "SharePointTenantSettings.Read.All",
    "Sites.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
)

#: Upper bound on OneDrive items examined per user; a cap that trips is
#: recorded as partial coverage, never silently.
MAX_DRIVE_PAGES = 10


def _keep(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: item[k] for k in fields if k in item}


# -- collectors ------------------------------------------------------------------


def _organization(c: GraphReadOnly, _ctx: dict[str, Any]) -> dict[str, Any]:
    [org] = c.get("organization", {"$select": "id,displayName,verifiedDomains,createdDateTime"})["value"]
    return {
        "id": org.get("id"),
        "organization_name": (org.get("displayName") or "").strip(),
        "created": org.get("createdDateTime"),
        "domains": [
            {"name": d.get("name"), "is_default": d.get("isDefault"), "is_initial": d.get("isInitial")}
            for d in org.get("verifiedDomains", [])
        ],
    }


USER_FIELDS = (
    "id",
    "userPrincipalName",
    "displayName",
    "accountEnabled",
    "userType",
    "createdDateTime",
    "signInActivity",
    "assignedLicenses",
    "externalUserState",
)


def _users(c: GraphReadOnly, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    users = c.paginate("users", {"$select": ",".join(USER_FIELDS), "$top": "999"})
    out = []
    for u in users:
        kept = _keep(u, USER_FIELDS)
        kept["assignedLicenses"] = len(u.get("assignedLicenses") or [])  # count only
        out.append(kept)
    ctx["users"] = out
    return out


def _mfa_registration(c: GraphReadOnly, _ctx: dict[str, Any]) -> dict[str, Any]:
    rows = c.paginate("reports/authenticationMethods/userRegistrationDetails")
    fields = (
        "id",
        "userPrincipalName",
        "isAdmin",
        "isMfaRegistered",
        "isMfaCapable",
        "isPasswordlessCapable",
        "methodsRegistered",
        "lastUpdatedDateTime",
    )
    return {"entries": [_keep(r, fields) for r in rows]}


def _auth_methods(c: GraphReadOnly, ctx: dict[str, Any]) -> dict[str, Any]:
    """Each member's registered sign-in method *types*, never their details.

    Read directly per user because the registration report above can lag by
    a day or more on a new tenant (it returned no rows on day one).
    """
    entries: dict[str, list[dict[str, Any]]] = {}
    failed: list[str] = []
    for u in ctx.get("users", []):
        if u.get("userType") == "Guest":
            continue
        try:
            methods = c.get(f"users/{u['id']}/authentication/methods").get("value", [])
        except GraphError as exc:
            logger.warning("Sign-in methods unreadable for %s: %s", u.get("userPrincipalName"), exc.code)
            failed.append(str(u.get("userPrincipalName")))
            continue
        entries[u["id"]] = [
            {
                "type": str(m.get("@odata.type", "")).rsplit(".", 1)[-1],
                "created": m.get("createdDateTime"),
            }
            for m in methods
        ]
    if failed:
        ctx["partial"]["m365.auth_methods"] = (
            f"Sign-in methods could not be read for {len(failed)} account(s): {', '.join(sorted(failed))}."
        )
    return {"entries": entries}


def _roles(c: GraphReadOnly, _ctx: dict[str, Any]) -> dict[str, Any]:
    definitions = c.paginate(
        "roleManagement/directory/roleDefinitions", {"$select": "id,displayName,isBuiltIn,templateId"}
    )
    assignments = c.paginate(
        "roleManagement/directory/roleAssignments",
        {"$select": "id,principalId,roleDefinitionId,directoryScopeId"},
    )
    return {"definitions": definitions, "assignments": assignments}


def _groups(c: GraphReadOnly, _ctx: dict[str, Any]) -> list[dict[str, Any]]:
    return c.paginate(
        "groups",
        {
            "$select": "id,displayName,securityEnabled,isAssignableToRole,groupTypes,mailEnabled",
            "$top": "999",
        },
    )


SP_FIELDS = (
    "id",
    "appId",
    "displayName",
    "appOwnerOrganizationId",
    "servicePrincipalType",
    "accountEnabled",
    "verifiedPublisher",
    "publisherName",
    "createdDateTime",
)


def _service_principals(c: GraphReadOnly, _ctx: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _keep(sp, SP_FIELDS)
        for sp in c.paginate("servicePrincipals", {"$select": ",".join(SP_FIELDS), "$top": "999"})
    ]


def _graph_permissions(c: GraphReadOnly, _ctx: dict[str, Any]) -> dict[str, Any]:
    """Graph's own catalogue (to name application permissions) and what was
    granted against it, both delegated (oauth2PermissionGrants) and app-only
    (appRoleAssignedTo), plus the tenant's "low impact" classifications."""
    [graph] = c.get(
        "servicePrincipals",
        {"$filter": f"appId eq '{GRAPH_APP_ID}'", "$select": "id,appRoles"},
    )["value"]
    app_roles = {r["id"]: r.get("value") for r in graph.get("appRoles", [])}
    assigned = c.paginate(f"servicePrincipals/{graph['id']}/appRoleAssignedTo", {"$top": "999"})
    classifications = c.paginate(f"servicePrincipals/{graph['id']}/delegatedPermissionClassifications")
    delegated = c.paginate("oauth2PermissionGrants")
    return {
        "graph_service_principal_id": graph["id"],
        "application_grants": [
            {
                "client_sp_id": a.get("principalId"),
                "client_name": a.get("principalDisplayName"),
                "permission": app_roles.get(a.get("appRoleId"), a.get("appRoleId")),
                "created": a.get("createdDateTime"),
            }
            for a in assigned
            if a.get("principalType") == "ServicePrincipal"
        ],
        "delegated_grants": [
            _keep(g, ("id", "clientId", "consentType", "principalId", "resourceId", "scope"))
            for g in delegated
        ],
        "low_impact_classifications": [
            _keep(x, ("permissionName", "classification")) for x in classifications
        ],
    }


def _applications(c: GraphReadOnly, _ctx: dict[str, Any]) -> list[dict[str, Any]]:
    apps = c.paginate(
        "applications",
        {
            "$select": "id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials",
            "$top": "999",
        },
    )
    out = []
    for a in apps:
        out.append(
            {
                **_keep(a, ("id", "appId", "displayName", "signInAudience", "createdDateTime")),
                # Dates and kind only: secret `hint` characters and key material are dropped.
                "secrets": [
                    _keep(p, ("keyId", "startDateTime", "endDateTime"))
                    for p in a.get("passwordCredentials", [])
                ],
                "certificates": [
                    _keep(k, ("keyId", "startDateTime", "endDateTime", "type"))
                    for k in a.get("keyCredentials", [])
                ],
            }
        )
    return out


def _policies(c: GraphReadOnly, _ctx: dict[str, Any]) -> dict[str, Any]:
    defaults = c.get("policies/identitySecurityDefaultsEnforcementPolicy")
    authz = c.get("policies/authorizationPolicy")
    ca = c.paginate("identity/conditionalAccess/policies")
    return {
        "security_defaults_enabled": defaults.get("isEnabled"),
        "authorization": {
            "permission_grant_policies": (authz.get("defaultUserRolePermissions") or {}).get(
                "permissionGrantPoliciesAssigned", []
            ),
            "users_can_register_apps": (authz.get("defaultUserRolePermissions") or {}).get(
                "allowedToCreateApps"
            ),
            "allow_invites_from": authz.get("allowInvitesFrom"),
            "guest_user_role_id": authz.get("guestUserRoleId"),
        },
        "conditional_access": [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "state": p.get("state"),
                "users": ((p.get("conditions") or {}).get("users")) or {},
                "client_app_types": ((p.get("conditions") or {}).get("clientAppTypes")) or [],
                "grant_controls": ((p.get("grantControls") or {}).get("builtInControls")) or [],
            }
            for p in ca
        ],
    }


def _sharepoint_settings(c: GraphReadOnly, _ctx: dict[str, Any]) -> dict[str, Any]:
    s = c.get("admin/sharepoint/settings")
    return _keep(
        s,
        (
            "sharingCapability",
            "sharingDomainRestrictionMode",
            "isResharingByExternalUsersEnabled",
            "oneDriveSharingCapability",
            "siteCreationDefaultStorageLimitInMB",
        ),
    )


def _public_files(c: GraphReadOnly, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """OneDrive items shared through an "Anyone" link, per user.

    App-only access can read a blocked user's OneDrive (unlike Google, which
    cannot search as a suspended account), so departed owners are covered
    directly. Listed with `delta`, which walks the whole drive; `search` fails
    app-only (HTTP 500 generalException, seen live on day one). Then one read
    per shared item for its permissions. Names and link scope only; contents are never fetched.
    """
    found: list[dict[str, Any]] = []
    skipped: list[str] = []
    for u in ctx.get("users", []):
        if u.get("userType") == "Guest" or not u.get("assignedLicenses"):
            continue  # guests and unlicensed accounts have no OneDrive
        try:
            items = c.paginate(
                f"users/{u['id']}/drive/root/delta",
                {"$select": "id,name,shared,deleted,parentReference,lastModifiedDateTime,file,folder"},
                max_pages=MAX_DRIVE_PAGES,
            )
        except GraphError as exc:
            if exc.status == 404:
                continue  # OneDrive not provisioned yet (never signed in)
            skipped.append(f"{u.get('userPrincipalName')} ({exc.code})")
            continue
        for item in items:
            if "shared" not in item or "deleted" in item:
                continue
            drive_id = (item.get("parentReference") or {}).get("driveId")
            try:
                perms = c.get(f"drives/{drive_id}/items/{item['id']}/permissions").get("value", [])
            except GraphError as exc:
                skipped.append(f"{item.get('name')} ({exc.code})")
                continue
            scopes = sorted(
                {
                    str((p.get("link") or {}).get("scope"))
                    for p in perms
                    if (p.get("link") or {}).get("scope")
                }
            )
            if "anonymous" in scopes:
                found.append(
                    {
                        "id": item["id"],
                        "name": item.get("name"),
                        "owner_id": u["id"],
                        "owner": u.get("userPrincipalName"),
                        "owner_enabled": u.get("accountEnabled"),
                        "kind": "folder" if "folder" in item else "file",
                        "modified": item.get("lastModifiedDateTime"),
                        "link_scopes": scopes,
                    }
                )
    if skipped:
        ctx["partial"]["m365.public_files"] = (
            "Some OneDrive locations could not be checked for public links: " + "; ".join(skipped) + "."
        )
    return found


def _audit_readiness(c: GraphReadOnly, _ctx: dict[str, Any]) -> dict[str, Any]:
    since = (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    streams: dict[str, Any] = {}
    # The two logs name their timestamp differently (a 400 on day one).
    for name, path, field in (
        ("directory_audit", "auditLogs/directoryAudits", "activityDateTime"),
        ("sign_ins", "auditLogs/signIns", "createdDateTime"),
    ):
        try:
            rows = c.get(path, {"$filter": f"{field} ge {since}", "$top": "50"}).get("value", [])
            streams[name] = {"available": True, "events_sampled": len(rows)}
        except GraphError as exc:
            streams[name] = {"available": False, "reason": f"HTTP {exc.status} {exc.code}"}
    return {"probe_window_days": 7, "streams": streams}


#: Order matters: users first (later collectors read ctx["users"]).
COLLECTORS: tuple[tuple[str, Callable[[GraphReadOnly, dict[str, Any]], Any]], ...] = (
    ("m365.organization", _organization),
    ("m365.users", _users),
    ("m365.mfa_registration", _mfa_registration),
    ("m365.auth_methods", _auth_methods),
    ("m365.roles", _roles),
    ("m365.groups", _groups),
    ("m365.service_principals", _service_principals),
    ("m365.graph_permissions", _graph_permissions),
    ("m365.applications", _applications),
    ("m365.policies", _policies),
    ("m365.sharepoint_settings", _sharepoint_settings),
    ("m365.public_files", _public_files),
    ("m365.audit_readiness", _audit_readiness),
)


def _error(name: str, exc: GraphError) -> CollectionError:
    if exc.status in (401, 403):
        state, message = (
            Assessability.NOT_ASSESSABLE_PERMISSION,
            f"Access denied ({exc.status} {exc.code}). The app registration is missing a "
            "permission, or admin consent was not granted.",
        )
    elif exc.status in (400, 404) and "licen" in exc.message.lower():
        state, message = (
            Assessability.NOT_ASSESSABLE_LICENSE,
            f"Not available on this licence: {exc.message}",
        )
    else:
        state, message = Assessability.NOT_ASSESSABLE_ERROR, f"HTTP {exc.status} {exc.code}: {exc.message}"
    return CollectionError(collector=name, assessability=state, message=message, http_status=exc.status)


def collect(client: GraphReadOnly, *, tenant_id: str) -> Snapshot:
    started_at = datetime.now(UTC)
    ctx: dict[str, Any] = {"partial": {}}
    artifacts: dict[str, Any] = {}
    errors: list[CollectionError] = []

    for name, fn in COLLECTORS:
        try:
            logger.info("Collecting %s", name)
            artifacts[name] = fn(client, ctx)
        except GraphError as exc:
            errors.append(_error(name, exc))
            logger.warning("Collector %s degraded: %s", name, exc)

    # Read-only attestation: the guard refuses writes before they are sent;
    # this asserts none was even recorded.
    unsafe = sorted({c.method for c in client.calls} - {"GET", "HEAD"})
    if unsafe:
        raise RuntimeError(f"Read-only violation recorded: {unsafe}")

    collected_at = datetime.now(UTC)
    return Snapshot(
        snapshot_id=f"{collected_at:%Y%m%dT%H%M%S%f}"[:-3] + "Z-" + secrets.token_hex(4),
        tenant_id=tenant_id,
        platform=Platform.MICROSOFT_365,
        started_at=started_at,
        collected_at=collected_at,
        scopes_used=PERMISSIONS_USED,
        artifacts=artifacts,
        errors=tuple(errors),
        partial=ctx["partial"],
        api_calls=tuple(client.calls),
    )
