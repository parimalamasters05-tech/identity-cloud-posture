"""Google Workspace -> normalized tenant view.

Every provider quirk that needs explaining is handled here, once, so that no
rule has to know about it.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from icp.models.enums import (
    Assessability,
    CheckFamily,
    IdentityKind,
    Platform,
    ResourceKind,
)
from icp.models.identity import Identity, MfaMethod, OAuthGrant, OAuthScope
from icp.models.resource import DomainPolicy, Resource
from icp.models.snapshot import Snapshot
from icp.normalizers.base import (
    Application,
    AuditStream,
    CoverageGap,
    NormalizedTenant,
    TokenLogCoverage,
)
from icp.risk.scope_taxonomy import ScopeTaxonomy

logger = logging.getLogger(__name__)

#: Collector -> check families that become unassessable when it degrades.
#:
#: `google.mfa` is deliberately absent: enrollment comes from `google.users`,
#: and only method strength needs the usage report. The rule that needs it
#: declares so via `Rule.requires_collectors`.
_COLLECTOR_IMPACT: dict[str, tuple[CheckFamily, ...]] = {
    "google.users": (
        CheckFamily.MFA_COVERAGE,
        CheckFamily.STALE_ACCOUNTS,
        CheckFamily.ADMIN_ROLE_SPRAWL,
        # OAuth grants are enumerated per user, from this collector's list.
        CheckFamily.OAUTH_GRANTS,
        CheckFamily.SERVICE_ACCOUNT_PRIVILEGE,
    ),
    "google.roles": (CheckFamily.ADMIN_ROLE_SPRAWL,),
    "google.role_assignments": (CheckFamily.ADMIN_ROLE_SPRAWL,),
    "google.oauth_tokens": (CheckFamily.OAUTH_GRANTS, CheckFamily.SERVICE_ACCOUNT_PRIVILEGE),
    "google.public_drive_items": (CheckFamily.EXTERNAL_SHARING,),
    "google.drive_settings": (CheckFamily.EXTERNAL_SHARING,),
    # Deliberately absent: google.workspace_policies. Only GWS-SHR-002 needs it,
    # and that rule reports "not assessed" itself when the policy is unknown.
    "google.audit_readiness": (CheckFamily.LOGGING_READINESS,),
}


def normalize(snapshot: Snapshot, taxonomy: ScopeTaxonomy | None = None) -> NormalizedTenant:
    taxonomy = taxonomy or ScopeTaxonomy.load_default()

    tenant = NormalizedTenant(
        platform=Platform.GOOGLE_WORKSPACE,
        tenant_id=snapshot.tenant_id,
        snapshot=snapshot,
    )

    role_index = _build_role_index(snapshot)
    tenant.identities = _normalize_users(snapshot, role_index)
    tenant.identities += _normalize_groups(snapshot)
    tenant.grants = _normalize_grants(snapshot, taxonomy)
    tenant.token_log = _normalize_token_log(snapshot)
    tenant.organization_name, tenant.primary_domain = _organization(snapshot)
    mfa_payload = snapshot.artifact("google.mfa")
    if isinstance(mfa_payload, dict) and mfa_payload.get("report_date"):
        tenant.mfa_report_date = str(mfa_payload["report_date"])
    tenant.applications = _build_applications(tenant)
    tenant.resources = _normalize_resources(snapshot)
    tenant.audit_streams = _normalize_audit(snapshot)
    tenant.policy = _normalize_policy(snapshot)
    tenant.assessability = _build_assessability(snapshot)
    tenant.coverage = _build_coverage(snapshot, tenant)
    tenant.coverage_gaps = _build_coverage_gaps(snapshot, tenant)

    return tenant


# -- users ---------------------------------------------------------------------


def _build_role_index(snapshot: Snapshot) -> dict[str, list[dict[str, Any]]]:
    """Map user id -> the role definitions assigned to them."""
    roles = {str(r.get("roleId")): r for r in snapshot.artifact("google.roles") or []}
    index: dict[str, list[dict[str, Any]]] = {}
    for assignment in snapshot.artifact("google.role_assignments") or []:
        if assignment.get("assigneeType") not in (None, "user", "USER"):
            continue
        user_id = str(assignment.get("assignedTo"))
        role = roles.get(str(assignment.get("roleId")))
        if role:
            index.setdefault(user_id, []).append(role)
    return index


def _normalize_users(snapshot: Snapshot, role_index: dict[str, list[dict[str, Any]]]) -> list[Identity]:
    mfa_index = _build_mfa_index(snapshot)
    identities: list[Identity] = []

    for raw in snapshot.artifact("google.users") or []:
        user_id = str(raw.get("id"))
        roles = role_index.get(user_id, [])
        role_names = tuple(str(r.get("roleName")) for r in roles)

        # `isAdmin` is Google's super-admin flag. A role explicitly marked
        # isSuperAdminRole also counts, which catches custom super-admin roles.
        is_super = bool(raw.get("isAdmin")) or any(r.get("isSuperAdminRole") for r in roles)
        is_delegated = bool(raw.get("isDelegatedAdmin"))

        mfa = mfa_index.get(user_id) or mfa_index.get(str(raw.get("primaryEmail")), {})
        enrolled = bool(raw.get("isEnrolledIn2Sv", mfa.get("is_2sv_enrolled", False)))
        enforced = bool(raw.get("isEnforcedIn2Sv", mfa.get("is_2sv_enforced", False)))

        methods: list[MfaMethod] = []
        # Google's field names; `security_key_count` is kept only so snapshots
        # frozen before the fix still load.
        key_count = int(mfa.get("num_security_keys") or mfa.get("security_key_count") or 0)
        passkeys = int(mfa.get("num_passkeys_enrolled") or 0)
        # With a report present, an account missing from it (Google flags such
        # days PARTIAL_DATA_AVAILABLE) has an unknown method, not a weak one.
        method_known = bool(mfa) or not mfa_index
        if key_count > 0:
            methods.append(MfaMethod(method="security_key", is_phishing_resistant=True))
        if passkeys > 0:
            methods.append(MfaMethod(method="passkey", is_phishing_resistant=True))
        if not methods and enrolled and method_known:
            # Google does not disclose which weaker factor is in use. Recording it
            # as unknown-and-not-phishing-resistant is the honest reading, and the
            # rule lowers its confidence accordingly.
            methods.append(MfaMethod(method="unspecified", is_phishing_resistant=False))

        identities.append(
            Identity(
                id=user_id,
                platform=Platform.GOOGLE_WORKSPACE,
                kind=IdentityKind.USER,
                primary_email=raw.get("primaryEmail"),
                display_name=(raw.get("name") or {}).get("fullName"),
                suspended=bool(raw.get("suspended")),
                archived=bool(raw.get("archived")),
                is_admin=is_super or is_delegated,
                is_super_admin=is_super,
                is_delegated_admin=is_delegated,
                admin_roles=role_names,
                mfa_enrolled=enrolled,
                mfa_enforced=enforced,
                mfa_methods=tuple(methods),
                mfa_method_known=method_known,
                created_at=_parse_time(raw.get("creationTime")),
                last_login_at=_parse_time(raw.get("lastLoginTime")),
                org_unit=raw.get("orgUnitPath"),
            )
        )
    return identities


def _build_mfa_index(snapshot: Snapshot) -> dict[str, dict[str, Any]]:
    payload = snapshot.artifact("google.mfa") or {}
    index: dict[str, dict[str, Any]] = {}
    for entry in payload.get("entries", []) if isinstance(payload, dict) else []:
        for key in (entry.get("profile_id"), entry.get("email")):
            if key:
                index[str(key)] = entry
    return index


def _normalize_groups(snapshot: Snapshot) -> list[Identity]:
    return [
        Identity(
            id=str(raw.get("id")),
            platform=Platform.GOOGLE_WORKSPACE,
            kind=IdentityKind.GROUP,
            primary_email=raw.get("email"),
            display_name=raw.get("name"),
        )
        for raw in snapshot.artifact("google.groups") or []
    ]


# -- oauth ---------------------------------------------------------------------


def _organization(snapshot: Snapshot) -> tuple[str | None, str | None]:
    """(organization name, primary domain), both as Google reports them."""
    customer = snapshot.artifacts.get("google.customer")
    name = (customer or {}).get("organization_name") if isinstance(customer, dict) else None

    domains = (snapshot.artifacts.get("google.drive_settings") or {}).get("domains", []) or []
    primary = next((d.get("domainName") for d in domains if d.get("isPrimary")), None)
    if not primary and isinstance(customer, dict):
        primary = customer.get("customer_domain")
    return (name or None), (primary or None)


def _normalize_token_log(snapshot: Snapshot) -> TokenLogCoverage | None:
    payload = snapshot.artifacts.get("google.token_activity")
    if not isinstance(payload, dict):
        return None
    window_start = _parse_time(payload.get("window_start"))
    if window_start is None:
        return None
    oldest = _parse_time(payload.get("oldest_event"))
    truncated = bool(payload.get("truncated"))
    return TokenLogCoverage(
        window_start=window_start,
        # A complete read covers the whole window, however old its oldest event.
        covered_since=(oldest or window_start) if truncated else window_start,
        activity_recorded=bool(payload.get("activity_recorded")),
        truncated=truncated,
        event_names=dict(payload.get("event_names") or {}),
    )


def _token_log_index(snapshot: Snapshot) -> dict[tuple[str, str], dict[str, Any]]:
    payload = snapshot.artifacts.get("google.token_activity")
    apps = payload.get("apps", []) if isinstance(payload, dict) else []
    return {(str(r.get("client_id")), str(r.get("user", "")).lower()): r for r in apps or []}


def _normalize_grants(snapshot: Snapshot, taxonomy: ScopeTaxonomy) -> list[OAuthGrant]:
    payload = snapshot.artifact("google.oauth_tokens") or {}
    raw_grants = payload.get("grants", []) if isinstance(payload, dict) else payload
    log = _token_log_index(snapshot)

    grants: list[OAuthGrant] = []
    for raw in raw_grants or []:
        scope_strings = tuple(raw.get("scopes") or ())
        client_id = str(raw.get("clientId"))
        history = log.get((client_id, str(raw.get("userKey") or "").lower()), {})
        first_party_kind = taxonomy.first_party_kind(client_id, scope_strings)
        scopes = tuple(
            OAuthScope(
                scope=s,
                tier=taxonomy.tier_for(s),
                description=taxonomy.description_for(s),
            )
            for s in scope_strings
        )
        grants.append(
            OAuthGrant(
                platform=Platform.GOOGLE_WORKSPACE,
                client_id=client_id,
                app_name=raw.get("displayText"),
                user_id=str(raw.get("userId") or raw.get("userKey")),
                user_email=raw.get("userKey"),
                scopes=scopes,
                is_native_app=bool(raw.get("nativeApp")),
                is_anonymous_app=bool(raw.get("anonymous")),
                last_authorized_at=_parse_time(history.get("last_authorized")),
                last_used_at=_parse_time(history.get("last_activity")),
                is_first_party=first_party_kind is not None,
                first_party_kind=first_party_kind,
            )
        )
    return grants


def _build_applications(tenant: NormalizedTenant) -> list[Application]:
    """One inventory row per application, including those with no finding."""
    by_client: dict[str, list[OAuthGrant]] = {}
    for grant in tenant.grants:
        by_client.setdefault(grant.client_id, []).append(grant)

    inactive = {u.id for u in tenant.users if u.suspended or u.archived}
    apps = []
    for client_id, grants in by_client.items():
        scopes = sorted({s for g in grants for s in g.scope_strings})
        users = {g.user_id: g.user_email or g.user_id for g in grants}
        authorized = [g.last_authorized_at for g in grants if g.last_authorized_at]
        used = [g.last_used_at for g in grants if g.last_used_at]
        apps.append(
            Application(
                client_id=client_id,
                name=next((g.app_name for g in grants if g.app_name), None) or client_id,
                is_first_party=grants[0].is_first_party,
                first_party_kind=grants[0].first_party_kind,
                is_anonymous=any(g.is_anonymous_app for g in grants),
                users=tuple(sorted(users.values())),
                active_users=sum(1 for uid in users if uid not in inactive),
                suspended_users=sum(1 for uid in users if uid in inactive),
                scopes=tuple(scopes),
                max_tier=max((g.max_tier for g in grants), key=lambda t: t.weight),
                last_authorized_at=max(authorized) if authorized else None,
                last_used_at=max(used) if used else None,
            )
        )
    # Highest blast radius first, then reach: the order a reviewer should read it.
    return sorted(apps, key=lambda a: (-a.max_tier.weight, -len(a.users), a.name.lower()))


# -- resources, audit, policy --------------------------------------------------


def _normalize_resources(snapshot: Snapshot) -> list[Resource]:
    resources: list[Resource] = []
    for raw in snapshot.artifact("google.public_drive_items") or []:
        owners = raw.get("owners") or []
        resources.append(
            Resource(
                id=str(raw.get("id")),
                platform=Platform.GOOGLE_WORKSPACE,
                kind=ResourceKind.SHARED_DRIVE,
                name=str(raw.get("name") or "(unnamed)"),
                externally_shared=True,
                publicly_accessible=True,
                owner_id=owners[0] if owners else None,
                settings={
                    "mimeType": raw.get("mimeType"),
                    "modifiedTime": raw.get("modifiedTime"),
                    # "drive_search" (read directly) or "audit_log" (owner could not
                    # be searched; last recorded change made it public).
                    "source": raw.get("source", "drive_search"),
                    "made_public_at": raw.get("made_public_at"),
                },
            )
        )
    return resources


def _normalize_audit(snapshot: Snapshot) -> list[AuditStream]:
    payload = snapshot.artifact("google.audit_readiness") or {}
    window = int(payload.get("probe_window_days", 0)) if isinstance(payload, dict) else 0
    streams = payload.get("streams", {}) if isinstance(payload, dict) else {}
    return [
        AuditStream(
            name=name,
            available=bool(info.get("available")),
            event_count_sampled=int(info.get("event_count_sampled") or 0),
            probe_window_days=window,
            reason=info.get("reason"),
        )
        for name, info in streams.items()
    ]


def _normalize_policy(snapshot: Snapshot) -> DomainPolicy:
    payload = snapshot.artifact("google.drive_settings") or {}
    domains = payload.get("domains", []) if isinstance(payload, dict) else []
    primary = next((d for d in domains if d.get("isPrimary")), None) or (domains[0] if domains else {})

    users = snapshot.artifact("google.users") or []
    enforced_ratio = sum(1 for u in users if u.get("isEnforcedIn2Sv")) / len(users) if users else 0.0

    sharing = _drive_sharing(snapshot)

    return DomainPolicy(
        platform=Platform.GOOGLE_WORKSPACE,
        domain=str(primary.get("domainName", "unknown")),
        mfa_enforced_org_wide=enforced_ratio >= 0.95,
        external_sharing_allowed=sharing["allowed"],
        external_sharing_warning_enabled=sharing["warned"],
        raw={"domains": domains, "drive_sharing": sharing},
    )


def _setting_value(value: dict[str, Any], name: str) -> Any:
    """Read a Policy API field in either spelling.

    Google's own settings reference lists these in snake_case in one table and
    camelCase in another; the JSON wire format is camelCase. Accept both rather
    than silently reading nothing.
    """
    if name in value:
        return value[name]
    head, *rest = name.split("_")
    return value.get(head + "".join(part.capitalize() for part in rest))


#: Google's documented defaults for drive_and_docs.external_sharing, which apply
#: to any field -- or whole setting -- a tenant has never changed. The warning
#: is ON by default; reading an absent field as "off" reports a control as
#: missing on nearly every tenant.
_DRIVE_SHARING_DEFAULTS = {
    "external_sharing_mode": "ALLOWED",
    "warn_for_external_sharing": True,
    "warn_for_sharing_outside_allowlisted_domains": True,
}


def _drive_sharing(snapshot: Snapshot) -> dict[str, Any]:
    """The least-protected Drive sharing policy anywhere in the organization.

    A setting can differ per organizational unit or group. One unit sharing
    externally with no warning is enough for the finding, so the answer is the
    weakest policy found, with the places it applies recorded as evidence.

    Three states, kept distinct:
      * artifact absent (collector degraded, or an older snapshot) -> unknown
      * read, but no Drive sharing policy returned -> Google's defaults apply
      * read, with policies -> evaluated; absent fields take their defaults

    Only an explicitly observed "warning off" can produce a finding. A field
    inherited from a parent unit's policy is not modelled, which can miss an
    inherited "off" but never invents one.
    """
    payload = snapshot.artifact("google.workspace_policies")
    if not isinstance(payload, dict) or "policies" not in payload:
        return {"allowed": None, "warned": None, "source": "not read", "policies": [], "unwarned": []}

    policies = [
        p
        for p in payload.get("policies") or []
        if p.get("setting_type") == "drive_and_docs.external_sharing"
    ]
    if not policies:
        return {
            "allowed": True,
            "warned": True,
            "source": "google default",
            "policies": [],
            "unwarned": [],
        }

    evaluated: list[dict[str, Any]] = []
    for policy in policies:
        value = policy.get("value") or {}

        def field(name: str, value: dict[str, Any] = value) -> Any:
            found = _setting_value(value, name)
            return _DRIVE_SHARING_DEFAULTS[name] if found is None else found

        mode = field("external_sharing_mode")
        allowed = mode in ("ALLOWED", "ALLOWLISTED_DOMAINS")
        warn_field = (
            "warn_for_external_sharing"
            if mode == "ALLOWED"
            else "warn_for_sharing_outside_allowlisted_domains"
        )
        warned = bool(field(warn_field)) if allowed else True
        evaluated.append(
            {
                "org_unit": policy.get("org_unit", ""),
                "group": policy.get("group", ""),
                "mode": mode,
                "warned": warned,
            }
        )

    unwarned = [p for p in evaluated if p["mode"] != "DISALLOWED" and not p["warned"]]
    return {
        "allowed": any(p["mode"] != "DISALLOWED" for p in evaluated),
        "warned": not unwarned,
        "source": "tenant policy",
        "policies": evaluated,
        "unwarned": unwarned,
    }


# -- assessability and coverage ------------------------------------------------


def _build_assessability(snapshot: Snapshot) -> dict[CheckFamily, tuple[Assessability, str]]:
    state: dict[CheckFamily, tuple[Assessability, str]] = {}
    for error in snapshot.errors:
        for family in _COLLECTOR_IMPACT.get(error.collector, ()):
            # Keep the first (most specific) reason recorded for each family.
            state.setdefault(family, (error.assessability, error.message))
    return state


def _build_coverage(snapshot: Snapshot, tenant: NormalizedTenant) -> dict[str, Any]:
    oauth = snapshot.artifact("google.oauth_tokens") or {}
    enumerated = oauth.get("users_enumerated") if isinstance(oauth, dict) else None
    total = oauth.get("users_total") if isinstance(oauth, dict) else None

    return {
        "users_total": len(tenant.users),
        "users_active": len(tenant.active_users),
        "groups_total": sum(1 for i in tenant.identities if i.kind == IdentityKind.GROUP),
        "oauth_users_enumerated": enumerated,
        "oauth_users_total": total,
        "oauth_coverage_pct": (round(100 * enumerated / total, 1) if enumerated and total else None),
        "degraded_collectors": list(snapshot.degraded_collectors()),
    }


def _build_coverage_gaps(snapshot: Snapshot, tenant: NormalizedTenant) -> list[CoverageGap]:
    gaps: list[CoverageGap] = []

    for collector, reason in sorted(snapshot.partial.items()):
        families = _COLLECTOR_IMPACT.get(collector, ())
        if families:
            gaps.append(CoverageGap(key=f"partial:{collector}", families=families, reason=reason))

    # Administrators Google's sign-in method report left out: the method check
    # skips them rather than calling them key-less, and the report says so.
    unreported = [u for u in tenant.admins if not u.suspended and u.mfa_enrolled and not u.mfa_method_known]
    if unreported:
        gaps.append(
            CoverageGap(
                key="partial:google.mfa",
                families=(CheckFamily.MFA_COVERAGE,),
                reason=(
                    f"Google's report of sign-in methods did not include "
                    f"{len(unreported)} administrator account{'s' if len(unreported) != 1 else ''}, "
                    "so whether they use a security key or passkey could not be checked. Google "
                    "marks such days as having partial data."
                ),
                missed=tuple((u.id, u.label) for u in unreported),
            )
        )

    oauth = snapshot.artifact("google.oauth_tokens")
    failed = oauth.get("failed_users", []) if isinstance(oauth, dict) else []
    if failed:
        missed = []
        for entry in failed:
            user_id = str(entry.get("user_id"))
            identity = tenant.identity_by_id(user_id)
            missed.append((user_id, identity.label if identity else user_id))
        total = oauth.get("users_total") or len(tenant.users)
        gaps.append(
            CoverageGap(
                key="partial:google.oauth_tokens",
                families=_COLLECTOR_IMPACT["google.oauth_tokens"],
                reason=(
                    f"Application authorizations could not be read for {len(failed)} of {total} "
                    "accounts, so any applications those accounts connected are not in this report."
                ),
                missed=tuple(missed),
            )
        )
    return gaps


def _parse_time(value: Any) -> datetime | None:
    """Parse Google's RFC 3339 timestamps, tolerating the epoch sentinel.

    Google returns 1970-01-01 for 'never logged in'. Treating that as a real
    login date would make every never-used account look ancient but active,
    which is exactly backwards, so it is mapped to None.
    """
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.year <= 1970:
        return None
    return parsed
