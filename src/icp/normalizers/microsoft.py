"""Microsoft 365 snapshot -> normalized tenant view.

Mirrors `normalizers/google.py`: the same Identity, OAuthGrant, Resource and
AuditStream types, so the risk model, ranking, delta and report treat both
platforms alike. Microsoft-only facts (app-only permissions, app credentials,
guests) go into the fields the Google normalizer leaves empty.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from icp.models.enums import Assessability, CheckFamily, IdentityKind, Platform, ResourceKind, ScopeTier
from icp.models.identity import Identity, MfaMethod, OAuthGrant, OAuthScope
from icp.models.resource import DomainPolicy, Resource
from icp.models.snapshot import Snapshot
from icp.normalizers.base import (
    AppCredential,
    Application,
    AppOnlyGrant,
    AuditStream,
    CoverageGap,
    NormalizedTenant,
)

logger = logging.getLogger(__name__)

#: Entra role template IDs are fixed across every tenant.
GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
#: Microsoft's own tenant: service principals it publishes are first-party.
MICROSOFT_TENANT_IDS = frozenset(
    {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
)

#: Sign-in method types (Graph @odata.type, without the namespace).
_METHODS: dict[str, tuple[str, bool]] = {
    "fido2AuthenticationMethod": ("security_key_or_passkey", True),
    "windowsHelloForBusinessAuthenticationMethod": ("windows_hello", True),
    "platformCredentialAuthenticationMethod": ("platform_passkey", True),
    "x509CertificateAuthenticationMethod": ("certificate", True),
    "microsoftAuthenticatorAuthenticationMethod": ("authenticator_app", False),
    "softwareOathAuthenticationMethod": ("totp", False),
    "phoneAuthenticationMethod": ("sms_or_voice", False),
}
#: Not a second factor: the password itself, and self-service reset methods.
_NOT_MFA = frozenset(
    {"passwordAuthenticationMethod", "emailAuthenticationMethod", "temporaryAccessPassAuthenticationMethod"}
)

_COLLECTOR_IMPACT: dict[str, tuple[CheckFamily, ...]] = {
    "m365.users": (
        CheckFamily.MFA_COVERAGE,
        CheckFamily.ADMIN_ROLE_SPRAWL,
        CheckFamily.STALE_ACCOUNTS,
        CheckFamily.OAUTH_GRANTS,
        CheckFamily.SERVICE_ACCOUNT_PRIVILEGE,
    ),
    "m365.auth_methods": (CheckFamily.MFA_COVERAGE,),
    "m365.roles": (CheckFamily.ADMIN_ROLE_SPRAWL,),
    "m365.service_principals": (CheckFamily.OAUTH_GRANTS, CheckFamily.SERVICE_ACCOUNT_PRIVILEGE),
    "m365.graph_permissions": (CheckFamily.OAUTH_GRANTS, CheckFamily.SERVICE_ACCOUNT_PRIVILEGE),
    "m365.applications": (CheckFamily.SERVICE_ACCOUNT_PRIVILEGE,),
    "m365.public_files": (CheckFamily.EXTERNAL_SHARING,),
    "m365.sharepoint_settings": (CheckFamily.EXTERNAL_SHARING,),
    "m365.audit_readiness": (CheckFamily.LOGGING_READINESS,),
    # m365.policies is deliberately absent: each rule that needs a policy says
    # "not assessed" itself when it is unknown, so one missing policy does not
    # silence a whole family.
}


# -- permission taxonomy -------------------------------------------------------------

_TAXONOMY_PATH = Path("config/graph_permission_taxonomy.yaml")


@lru_cache(maxsize=1)
def permission_tiers() -> dict[str, ScopeTier]:
    path = _TAXONOMY_PATH
    if not path.exists():
        for parent in [Path.cwd(), *Path(__file__).resolve().parents]:
            if (parent / _TAXONOMY_PATH).exists():
                path = parent / _TAXONOMY_PATH
                break
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        permission: ScopeTier(tier)
        for tier in ScopeTier
        if tier != ScopeTier.UNKNOWN
        for permission in data.get(tier.value, []) or []
    }


def tier_of(permission: str) -> ScopeTier:
    return permission_tiers().get(permission, ScopeTier.UNKNOWN)


# -- entry point ---------------------------------------------------------------------


def normalize(snapshot: Snapshot) -> NormalizedTenant:
    tenant = NormalizedTenant(
        platform=Platform.MICROSOFT_365, tenant_id=snapshot.tenant_id, snapshot=snapshot
    )
    org = snapshot.artifact("m365.organization") or {}
    tenant.organization_name = org.get("organization_name") or None
    default_domain = next((d["name"] for d in org.get("domains", []) if d.get("is_default")), None)
    tenant.primary_domain = default_domain

    assessor_id = str((snapshot.artifact("m365.assessor") or {}).get("client_id") or "")
    roles = _role_index(snapshot)
    members, guests = _users(snapshot, roles)
    tenant.identities = members
    tenant.guests = guests

    sps = {sp["id"]: sp for sp in snapshot.artifact("m365.service_principals") or []}
    tenant.grants = _delegated_grants(snapshot, sps, {u.id: u for u in members + guests})
    tenant.app_only_grants = _app_only_grants(snapshot, sps, assessor_id)
    tenant.app_credentials = _credentials(snapshot, assessor_id)
    tenant.applications = _applications(tenant)
    tenant.resources = _resources(snapshot)
    tenant.audit_streams = _audit(snapshot)
    tenant.policy = _policy(snapshot, default_domain or "")
    tenant.assessability = {
        family: (e.assessability, e.message)
        for e in reversed(snapshot.errors)
        for family in _COLLECTOR_IMPACT.get(e.collector, ())
    }
    tenant.coverage = _coverage(snapshot, tenant)
    tenant.coverage_gaps = [
        CoverageGap(key=f"partial:{name}", families=_COLLECTOR_IMPACT.get(name, ()), reason=reason)
        for name, reason in sorted(snapshot.partial.items())
        if _COLLECTOR_IMPACT.get(name)
    ]
    return tenant


# -- identities ----------------------------------------------------------------------


def _role_index(snapshot: Snapshot) -> dict[str, list[tuple[str, bool]]]:
    """principal id -> [(role name, is Global Administrator)]."""
    data = snapshot.artifact("m365.roles") or {}
    definitions = {d["id"]: d for d in data.get("definitions", [])}
    index: dict[str, list[tuple[str, bool]]] = {}
    for a in data.get("assignments", []):
        d = definitions.get(a.get("roleDefinitionId"), {})
        is_global = (d.get("templateId") or d.get("id")) == GLOBAL_ADMIN_TEMPLATE
        index.setdefault(str(a.get("principalId")), []).append(
            (d.get("displayName") or "Unknown role", is_global)
        )
    return index


def _users(
    snapshot: Snapshot, roles: dict[str, list[tuple[str, bool]]]
) -> tuple[list[Identity], list[Identity]]:
    methods_by_user = (snapshot.artifact("m365.auth_methods") or {}).get("entries", {})
    methods_read = snapshot.artifact("m365.auth_methods") is not None
    members: list[Identity] = []
    guests: list[Identity] = []
    for u in snapshot.artifact("m365.users") or []:
        held = roles.get(u["id"], [])
        types = [m.get("type", "") for m in methods_by_user.get(u["id"], [])]
        mfa = tuple(
            MfaMethod(method=_METHODS[t][0], is_phishing_resistant=_METHODS[t][1])
            for t in dict.fromkeys(types)
            if t in _METHODS
        )
        unknown_second_factor = any(t not in _METHODS and t not in _NOT_MFA for t in types)
        sign_in = u.get("signInActivity") or {}
        identity = Identity(
            id=u["id"],
            platform=Platform.MICROSOFT_365,
            kind=IdentityKind.USER,
            primary_email=u.get("userPrincipalName"),
            display_name=u.get("displayName"),
            suspended=u.get("accountEnabled") is False,
            is_admin=bool(held),
            admin_roles=tuple(sorted({name for name, _ in held})),
            is_super_admin=any(is_global for _, is_global in held),
            is_delegated_admin=bool(held) and not any(is_global for _, is_global in held),
            mfa_enrolled=bool(mfa) or unknown_second_factor,
            mfa_methods=mfa,
            mfa_method_known=methods_read and u["id"] in methods_by_user,
            created_at=_time(u.get("createdDateTime")),
            last_login_at=_time(
                sign_in.get("lastSuccessfulSignInDateTime") or sign_in.get("lastSignInDateTime")
            ),
        )
        (guests if u.get("userType") == "Guest" else members).append(identity)
    return members, guests


# -- applications ------------------------------------------------------------------


def _scopes(names: list[str]) -> tuple[OAuthScope, ...]:
    return tuple(OAuthScope(scope=n, tier=tier_of(n)) for n in dict.fromkeys(names) if n)


def _delegated_grants(
    snapshot: Snapshot, sps: dict[str, dict[str, Any]], people: dict[str, Identity]
) -> list[OAuthGrant]:
    data = snapshot.artifact("m365.graph_permissions") or {}
    grants: list[OAuthGrant] = []
    for g in data.get("delegated_grants", []):
        sp = sps.get(str(g.get("clientId")), {})
        first_party = sp.get("appOwnerOrganizationId") in MICROSOFT_TENANT_IDS
        everyone = g.get("consentType") == "AllPrincipals"
        person = people.get(str(g.get("principalId")))
        grants.append(
            OAuthGrant(
                platform=Platform.MICROSOFT_365,
                client_id=str(sp.get("appId") or g.get("clientId")),
                app_name=sp.get("displayName"),
                # "*" = consented by an administrator for every user in the organization.
                user_id="*" if everyone else str(g.get("principalId")),
                user_email="all users (administrator consent)"
                if everyone
                else (person.label if person else None),
                scopes=_scopes(str(g.get("scope") or "").split()),
                is_first_party=first_party,
                is_anonymous_app=not first_party
                and not (sp.get("verifiedPublisher") or {}).get("displayName"),
            )
        )
    return grants


def _app_only_grants(
    snapshot: Snapshot, sps: dict[str, dict[str, Any]], assessor_id: str
) -> list[AppOnlyGrant]:
    data = snapshot.artifact("m365.graph_permissions") or {}
    out = []
    for g in data.get("application_grants", []):
        sp = sps.get(str(g.get("client_sp_id")), {})
        app_id = str(sp.get("appId") or g.get("client_sp_id"))
        out.append(
            AppOnlyGrant(
                app_id=app_id,
                app_name=str(g.get("client_name") or sp.get("displayName") or app_id),
                permission=str(g.get("permission")),
                tier=tier_of(str(g.get("permission"))),
                is_assessor=bool(assessor_id) and app_id == assessor_id,
            )
        )
    return out


def _credentials(snapshot: Snapshot, assessor_id: str) -> list[AppCredential]:
    out = []
    for app in snapshot.artifact("m365.applications") or []:
        for kind, key in (("secret", "secrets"), ("certificate", "certificates")):
            for cred in app.get(key, []):
                out.append(
                    AppCredential(
                        app_id=str(app.get("appId")),
                        app_name=str(app.get("displayName")),
                        kind=kind,
                        starts=_time(cred.get("startDateTime")),
                        expires=_time(cred.get("endDateTime")),
                        is_assessor=bool(assessor_id) and app.get("appId") == assessor_id,
                    )
                )
    return out


def _applications(tenant: NormalizedTenant) -> list[Application]:
    """The inventory: one entry per app holding delegated access."""
    by_app: dict[str, list[OAuthGrant]] = {}
    for g in tenant.grants:
        by_app.setdefault(g.client_id, []).append(g)
    people = {u.id: u for u in tenant.identities}
    apps = []
    for client_id, grants in by_app.items():
        users = tuple(sorted({g.user_id for g in grants}))
        scopes = tuple(sorted({s for g in grants for s in g.scope_strings}))
        apps.append(
            Application(
                client_id=client_id,
                name=grants[0].app_name or client_id,
                is_first_party=grants[0].is_first_party,
                first_party_kind=None,
                is_anonymous=grants[0].is_anonymous_app,
                users=users,
                active_users=sum(1 for u in users if u == "*" or (u in people and not people[u].suspended)),
                suspended_users=sum(1 for u in users if u in people and people[u].suspended),
                scopes=scopes,
                max_tier=max((g.max_tier for g in grants), key=lambda t: t.weight),
                last_authorized_at=None,
                last_used_at=None,
            )
        )
    # Apps holding access by themselves belong in the inventory too, labelled
    # as such; the assessment's own app is listed so the client can remove it.
    app_only: dict[str, list[AppOnlyGrant]] = {}
    for held_grant in tenant.app_only_grants:
        app_only.setdefault(held_grant.app_id, []).append(held_grant)
    for app_id, held in app_only.items():
        listed = next((a for a in apps if a.client_id == app_id), None)
        if listed is not None:
            # Both kinds of access (seen live: Backup Sync Test held app-only
            # Mail.Read plus an admin-approved User.Read). Skipping it here once
            # showed the app as "Sign-in only". Merge, so the highest access
            # and the "works without a user" label show.
            apps[apps.index(listed)] = replace(
                listed,
                first_party_kind="assessor" if held[0].is_assessor else "app_only",
                scopes=tuple(sorted({*listed.scopes, *(h.permission for h in held)})),
                max_tier=max((listed.max_tier, *(h.tier for h in held)), key=lambda t: t.weight),
            )
            continue
        apps.append(
            Application(
                client_id=app_id,
                name=held[0].app_name,
                is_first_party=False,
                first_party_kind="assessor" if held[0].is_assessor else "app_only",
                is_anonymous=False,
                users=(),
                active_users=0,
                suspended_users=0,
                scopes=tuple(sorted(h.permission for h in held)),
                max_tier=max((h.tier for h in held), key=lambda t: t.weight),
                last_authorized_at=None,
                last_used_at=None,
            )
        )
    return sorted(apps, key=lambda a: (-a.max_tier.weight, a.name))


# -- resources, logs, policy ----------------------------------------------------------


def _resources(snapshot: Snapshot) -> list[Resource]:
    return [
        Resource(
            id=str(f["id"]),
            platform=Platform.MICROSOFT_365,
            kind=ResourceKind.SHARED_DRIVE,
            name=str(f.get("name") or "(unnamed)"),
            externally_shared=True,
            publicly_accessible=True,
            owner_id=f.get("owner"),
            settings={
                "owner_enabled": f.get("owner_enabled"),
                "kind": f.get("kind"),
                "modifiedTime": f.get("modified"),
                "source": "onedrive",
            },
        )
        for f in snapshot.artifact("m365.public_files") or []
    ]


def _audit(snapshot: Snapshot) -> list[AuditStream]:
    data = snapshot.artifact("m365.audit_readiness") or {}
    window = int(data.get("probe_window_days", 0) or 0)
    return [
        AuditStream(
            name=name,
            available=bool(s.get("available")),
            event_count_sampled=int(s.get("events_sampled", 0) or 0),
            probe_window_days=window,
            reason=s.get("reason"),
        )
        for name, s in (data.get("streams") or {}).items()
    ]


def _policy(snapshot: Snapshot, domain: str) -> DomainPolicy | None:
    policies = snapshot.artifact("m365.policies")
    sharing = snapshot.artifact("m365.sharepoint_settings") or {}
    grants = snapshot.artifact("m365.graph_permissions") or {}
    if policies is None:
        return None
    ca = policies.get("conditional_access", [])
    mfa_policies = [
        p
        for p in ca
        if p.get("state") == "enabled"
        and "mfa" in (p.get("grant_controls") or [])
        and "All" in ((p.get("users") or {}).get("includeUsers") or [])
        and "All" in ((p.get("applications") or {}).get("includeApplications") or [])
    ]
    capability = sharing.get("sharingCapability")
    return DomainPolicy(
        platform=Platform.MICROSOFT_365,
        domain=domain,
        mfa_enforced_org_wide=bool(policies.get("security_defaults_enabled")) or bool(mfa_policies),
        external_sharing_allowed=(capability != "disabled") if capability else None,
        link_sharing_default=capability,
        raw={
            "security_defaults_enabled": policies.get("security_defaults_enabled"),
            "conditional_access": [
                {"name": p.get("displayName"), "state": p.get("state"), "grant": p.get("grant_controls")}
                for p in ca
            ],
            "mfa_enforcing_policies": [p.get("displayName") for p in mfa_policies],
            # Enabled policies requiring a second step for administrator roles:
            # an admin with none registered is asked to set one up at next sign-in.
            "admin_mfa_policies": [
                p.get("displayName")
                for p in ca
                if p.get("state") == "enabled"
                and "mfa" in (p.get("grant_controls") or [])
                and (p.get("users") or {}).get("includeRoles")
            ],
            "consent_policies": (policies.get("authorization") or {}).get("permission_grant_policies", []),
            "users_can_register_apps": (policies.get("authorization") or {}).get("users_can_register_apps"),
            "allow_invites_from": (policies.get("authorization") or {}).get("allow_invites_from"),
            "low_impact_permissions": sorted(
                x.get("permissionName")
                for x in grants.get("low_impact_classifications", [])
                if x.get("permissionName")
            ),
            "sharing_capability": capability,
            "resharing_by_guests": sharing.get("isResharingByExternalUsersEnabled"),
        },
    )


def _coverage(snapshot: Snapshot, tenant: NormalizedTenant) -> dict[str, Any]:
    with_sign_in = sum(1 for u in tenant.users if u.last_login_at)
    return {
        "users_total": len(tenant.users),
        "users_active": len(tenant.active_users),
        "guests_total": len(tenant.guests),
        # Microsoft fills last-sign-in times with a delay; on a new tenant every
        # account shows none. Age-based checks need at least one to be meaningful.
        "sign_in_data_available": with_sign_in > 0,
        "users_with_sign_in_data": with_sign_in,
        "degraded_collectors": list(snapshot.degraded_collectors()),
        "assessability_note": {
            str(f): str(a) for f, (a, _) in tenant.assessability.items() if a != Assessability.ASSESSED
        },
    }


def _time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
