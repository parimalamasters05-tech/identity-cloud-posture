"""Microsoft 365 preflight: does each granted permission actually work?

One small GET per permission (first item only, IDs only), so a missing grant,
an unconsented permission or a licence gap shows up before any collector is
written or any client data is read. Prints counts and Microsoft's error codes,
never names or content.
"""

from __future__ import annotations

from dataclasses import dataclass

from icp.security.graph_readonly import GraphError, GraphReadOnly


@dataclass(frozen=True)
class Probe:
    permission: str
    what: str
    path: str
    params: dict[str, str]


PROBES: tuple[Probe, ...] = (
    Probe("User.Read.All", "users", "users", {"$top": "1", "$select": "id"}),
    Probe("Directory.Read.All", "groups", "groups", {"$top": "1", "$select": "id"}),
    Probe("Directory.Read.All", "delegated app grants", "oauth2PermissionGrants", {"$top": "1"}),
    Probe(
        "AuditLog.Read.All",
        "last sign-in per user (needs Entra ID P1)",
        "users",
        {"$top": "1", "$select": "id,signInActivity"},
    ),
    Probe("AuditLog.Read.All", "directory audit log", "auditLogs/directoryAudits", {"$top": "1"}),
    Probe("AuditLog.Read.All", "sign-in log (needs Entra ID P1)", "auditLogs/signIns", {"$top": "1"}),
    Probe(
        "UserAuthenticationMethod.Read.All + AuditLog.Read.All",
        "MFA registration report",
        "reports/authenticationMethods/userRegistrationDetails",
        {"$top": "1"},
    ),
    Probe(
        "RoleManagement.Read.Directory",
        "admin role assignments",
        "roleManagement/directory/roleAssignments",
        {"$top": "1"},
    ),
    Probe("Policy.Read.All", "security defaults", "policies/identitySecurityDefaultsEnforcementPolicy", {}),
    Probe(
        "Policy.Read.All",
        "Conditional Access policies",
        "identity/conditionalAccess/policies",
        {"$top": "1"},
    ),
    Probe("Policy.Read.All", "user consent settings", "policies/authorizationPolicy", {}),
    Probe("Application.Read.All", "app registrations", "applications", {"$top": "1", "$select": "id"}),
    Probe(
        "Application.Read.All", "service principals", "servicePrincipals", {"$top": "1", "$select": "id"}
    ),
    Probe(
        "SharePointTenantSettings.Read.All", "organization sharing setting", "admin/sharepoint/settings", {}
    ),
    Probe("Sites.Read.All", "sites (metadata only)", "sites/root", {"$select": "id"}),
)


@dataclass(frozen=True)
class ProbeResult:
    probe: Probe
    ok: bool
    detail: str


def run(client: GraphReadOnly) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    first_user: str | None = None
    for probe in PROBES:
        try:
            payload = client.get(probe.path, probe.params)
            count = len(payload.get("value", [])) if "value" in payload else 1
            if probe.path == "users" and payload.get("value") and first_user is None:
                first_user = payload["value"][0].get("id")
            results.append(
                ProbeResult(probe, True, f"readable ({count} item{'s' if count != 1 else ''} returned)")
            )
        except GraphError as exc:
            results.append(ProbeResult(probe, False, f"HTTP {exc.status} {exc.code}"))

    # Per-user sign-in methods need a user ID; the first one is enough.
    methods = Probe(
        "UserAuthenticationMethod.Read.All",
        "one user's sign-in methods",
        "users/{id}/authentication/methods",
        {},
    )
    if first_user:
        try:
            payload = client.get(f"users/{first_user}/authentication/methods")
            results.append(
                ProbeResult(methods, True, f"readable ({len(payload.get('value', []))} methods)")
            )
        except GraphError as exc:
            results.append(ProbeResult(methods, False, f"HTTP {exc.status} {exc.code}"))
    else:
        results.append(ProbeResult(methods, False, "skipped: no user ID from the users probe"))
    return results
