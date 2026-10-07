"""Microsoft 365 rules: the seven check families, read from the normalized view.

Kept apart from the Google rules on purpose. The selection logic is often the
same idea, but the evidence a client checks against (which Entra field, which
admin centre page) and the fix are not, and the Google output is locked by the
week-4 baseline. Impact and exposure follow the Google equivalents so the two
platforms rank on one scale; Microsoft-only checks are marked as such.

Every rule here was seeded and seen on the dev tenant on 6 Oct 2026.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from icp.models.enums import CheckFamily, Confidence, Platform, ScopeTier
from icp.models.finding import AffectedEntity, Evidence, Finding
from icp.normalizers.base import NormalizedTenant
from icp.rules.admin_role_sprawl import _ABSOLUTE_CEILING, _MINIMUM_ALLOWED, _RATIO_CEILING
from icp.rules.base import Rule, RuleContext, RuleNotAssessable, entity_from_identity, plural, register

M365 = (Platform.MICROSOFT_365,)
_DATA_TIERS = (ScopeTier.FULL_DATA_READ, ScopeTier.FULL_DATA_WRITE, ScopeTier.ADMIN_EQUIVALENT)

_NO_SIGN_IN_DATA = (
    "Microsoft had not yet recorded a last sign-in time for any account in this organization, "
    "so inactive accounts cannot be told apart from active ones. Microsoft fills these in with a "
    "delay, and a recently created organization shows none."
)


def _day(value: datetime | None) -> str:
    """'5 October 2028', the report's date style."""
    return f"{value.day} {value:%B %Y}" if value else "an unknown date"


def _setting(label: str) -> AffectedEntity:
    return AffectedEntity(id=f"setting:{label}", kind="setting", label=label, is_privileged=False)


def _app(app_id: str, name: str) -> AffectedEntity:
    return AffectedEntity(id=app_id, kind="application", label=name, is_privileged=False)


def _require_policy(tenant: NormalizedTenant) -> dict:
    if tenant.policy is None:
        raise RuleNotAssessable("The organization's sign-in and sharing policies could not be read.")
    return tenant.policy.raw


class M365Rule(Rule):
    platforms = M365


# -- 1. Second sign-in step (multi-factor) ------------------------------------------------


@register
class M365AdminsWithoutMfa(M365Rule):
    rule_id = "M365-MFA-001"
    check_family = CheckFamily.MFA_COVERAGE
    title = "Administrator accounts without a second sign-in step"
    impact = 5
    exposure = 5
    remediation_key = "m365.mfa.enforce_admins"
    framework_refs = ("PR.AA-03", "PR.AA-05")
    default_effort_hours = 1.0
    requires_collectors = ("m365.auth_methods",)

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        affected = [
            u for u in tenant.admins if not u.suspended and u.mfa_method_known and not u.mfa_enrolled
        ]
        if not affected:
            return []
        # Seen live: "Require multifactor authentication for admins" was on, but
        # these admins had never registered a method. The policy then asks for
        # one at the next sign-in, from whoever has the password.
        policies = (tenant.policy.raw if tenant.policy else {}).get("admin_mfa_policies", [])
        pending = (
            f" The policy '{policies[0]}' will ask for a second step at the next sign-in, but none is set "
            "up yet, so whoever signs in next with the password, including someone who stole it, chooses it."
            if policies
            else ""
        )
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(affected), 'administrator account')} with no second sign-in step",
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="m365.auth_methods",
                        pointer=f"/m365.auth_methods/entries/{u.id}",
                        summary=(
                            f"{u.label} holds {', '.join(u.admin_roles)} and has no sign-in method "
                            "other than a password." + pending
                        ),
                        observed_values={"roles": ", ".join(u.admin_roles), "second_factor": False},
                    )
                    for u in affected
                ],
            )
        ]


@register
class M365UsersWithoutMfa(M365Rule):
    rule_id = "M365-MFA-002"
    check_family = CheckFamily.MFA_COVERAGE
    title = "Staff accounts without a second sign-in step"
    impact = 4
    exposure = 4
    remediation_key = "m365.mfa.enforce_all_users"
    framework_refs = ("PR.AA-03",)
    default_effort_hours = 3.0
    requires_collectors = ("m365.auth_methods",)

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        active = [u for u in tenant.active_users if u.mfa_method_known]
        affected = [u for u in active if not u.is_privileged and not u.mfa_enrolled]
        if not affected:
            return []
        total = len(active) or 1
        pct = round(100 * (total - len(affected)) / total, 1)
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{len(affected)} of {total} active accounts have no second sign-in step ({pct}% coverage)",
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="m365.auth_methods",
                        pointer="/m365.auth_methods/entries",
                        summary=(
                            f"{plural(len(affected), 'active staff account')} (not administrators) can sign in "
                            "with a password alone."
                        ),
                        observed_values={"without_second_factor": len(affected), "active_accounts": total},
                    )
                ],
            )
        ]


@register
class M365AdminsWithPhishableMfa(M365Rule):
    rule_id = "M365-MFA-003"
    check_family = CheckFamily.MFA_COVERAGE
    title = "Administrators without phishing-resistant sign-in"
    impact = 4
    exposure = 3
    remediation_key = "m365.mfa.phishing_resistant_admins"
    framework_refs = ("PR.AA-03",)
    default_effort_hours = 4.0
    requires_collectors = ("m365.auth_methods",)

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        affected = [
            u
            for u in tenant.admins
            if not u.suspended
            and u.mfa_method_known
            and u.mfa_enrolled
            and not u.has_phishing_resistant_mfa
        ]
        if not affected:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(affected), 'administrator account')} using a second step that can be phished",
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="m365.auth_methods",
                        pointer=f"/m365.auth_methods/entries/{u.id}",
                        summary=(
                            f"{u.label} signs in with {', '.join(m.method.replace('_', ' ') for m in u.mfa_methods)}, "
                            "which a fake sign-in page can relay to an attacker in real time. No security key "
                            "or passkey is registered."
                        ),
                        observed_values={"methods": ", ".join(m.method for m in u.mfa_methods)},
                    )
                    for u in affected
                ],
                confidence=Confidence.CONFIRMED,
            )
        ]


@register
class M365NoOrganizationWideMfa(M365Rule):
    """Microsoft-only: nothing requires a second step for the organization."""

    rule_id = "M365-MFA-004"
    check_family = CheckFamily.MFA_COVERAGE
    title = "No organization-wide requirement for a second sign-in step"
    impact = 5
    exposure = 4
    remediation_key = "m365.mfa.require_org_wide"
    framework_refs = ("PR.AA-03", "PR.AA-05")
    default_effort_hours = 2.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        raw = _require_policy(tenant)
        if tenant.policy and tenant.policy.mfa_enforced_org_wide:
            return []
        report_only = [p["name"] for p in raw.get("conditional_access", []) if p.get("state") != "enabled"]
        return [
            self.make_finding(
                tenant,
                ctx,
                title="Nothing requires a second sign-in step across the organization",
                entities=[_setting("Security defaults and Conditional Access")],
                evidence=[
                    Evidence(
                        collector="m365.policies",
                        pointer="/m365.policies",
                        summary=(
                            "Security defaults are turned off and no active Conditional Access policy "
                            "requires a second sign-in step for all users. Whether each account uses one is "
                            "left to the individual."
                            + (
                                f" {plural(len(report_only), 'policy is', 'policies are')} present but "
                                "not switched on (report-only or off)."
                                if report_only
                                else ""
                            )
                        ),
                        observed_values={
                            "security_defaults_enabled": bool(raw.get("security_defaults_enabled")),
                            "enforcing_policies": len(raw.get("mfa_enforcing_policies", [])),
                            "policies_not_enforced": len(report_only),
                        },
                    )
                ],
            )
        ]


# -- 2. Administrator roles ---------------------------------------------------------------


@register
class M365TooManyGlobalAdmins(M365Rule):
    rule_id = "M365-ADM-001"
    check_family = CheckFamily.ADMIN_ROLE_SPRAWL
    title = "More Global Administrators than the organization needs"
    impact = 4
    exposure = 3
    remediation_key = "m365.admins.reduce_global"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        globals_ = [u for u in tenant.super_admins if not u.suspended]
        active = max(len(tenant.active_users), 1)
        allowed = int(
            max(
                ctx.threshold("super_admin_minimum", _MINIMUM_ALLOWED),
                min(
                    ctx.threshold("super_admin_ceiling", _ABSOLUTE_CEILING),
                    int(active * ctx.threshold("super_admin_ratio", _RATIO_CEILING)),
                ),
            )
        )
        if len(globals_) <= allowed:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{len(globals_)} Global Administrator accounts for {plural(active, 'active user')} "
                    f"({round(100 * len(globals_) / active, 1)}% of staff)"
                ),
                entities=[entity_from_identity(u) for u in globals_],
                evidence=[
                    Evidence(
                        collector="m365.roles",
                        pointer="/m365.roles/assignments",
                        summary=(
                            f"{len(globals_)} accounts can change anything in the organization; "
                            f"{allowed} is enough for an organization of this size (one in use, one spare)."
                        ),
                        observed_values={"global_admins": len(globals_), "recommended_maximum": allowed},
                    )
                ],
            )
        ]


@register
class M365DormantAdmins(M365Rule):
    rule_id = "M365-ADM-002"
    check_family = CheckFamily.ADMIN_ROLE_SPRAWL
    title = "Administrator accounts not used recently"
    impact = 4
    exposure = 3
    remediation_key = "m365.admins.remove_dormant"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        if not tenant.coverage.get("sign_in_data_available"):
            raise RuleNotAssessable(_NO_SIGN_IN_DATA)
        days = int(ctx.threshold("dormant_admin_days", 45))
        cutoff = ctx.now - timedelta(days=days)
        affected = [
            u
            for u in tenant.admins
            if not u.suspended
            and (u.last_login_at or u.created_at)
            and (u.last_login_at or u.created_at) < cutoff  # type: ignore[operator]
        ]
        if not affected:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(affected), 'administrator account')} unused for over {days} days",
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="m365.users",
                        pointer=f"/m365.users/{u.id}/signInActivity",
                        summary=(
                            f"{u.label} holds {', '.join(u.admin_roles)} and last signed in "
                            f"{_day(u.last_login_at)}."
                            if u.last_login_at
                            else f"{u.label} holds {', '.join(u.admin_roles)} and has never signed in."
                        ),
                        observed_values={"last_sign_in": str(u.last_login_at or "never")},
                    )
                    for u in affected
                ],
            )
        ]


# -- 3. Unused and departed accounts --------------------------------------------------------


class _StaleBase(M365Rule):
    check_family = CheckFamily.STALE_ACCOUNTS
    framework_refs = ("PR.AA-01",)

    def _check_data(self, tenant: NormalizedTenant) -> None:
        if not tenant.coverage.get("sign_in_data_available"):
            raise RuleNotAssessable(_NO_SIGN_IN_DATA)


@register
class M365NeverSignedIn(_StaleBase):
    rule_id = "M365-STA-001"
    title = "Accounts that have never been used"
    impact = 3
    exposure = 3
    remediation_key = "m365.accounts.remove_unused"
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        self._check_data(tenant)
        days = int(ctx.threshold("never_signed_in_days", 30))
        cutoff = ctx.now - timedelta(days=days)
        affected = [
            u for u in tenant.active_users if not u.last_login_at and u.created_at and u.created_at < cutoff
        ]
        if not affected:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(affected), 'account')} created over {days} days ago and never used",
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="m365.users",
                        pointer="/m365.users",
                        summary=f"{plural(len(affected), 'enabled account')} {'has' if len(affected) == 1 else 'have'} never signed in.",
                        observed_values={"never_signed_in": len(affected), "days": days},
                    )
                ],
            )
        ]


@register
class M365DormantAccounts(_StaleBase):
    rule_id = "M365-STA-002"
    title = "Accounts not used for a long time"
    impact = 3
    exposure = 3
    remediation_key = "m365.accounts.remove_unused"
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        self._check_data(tenant)
        days = int(ctx.threshold("dormant_user_days", 90))
        cutoff = ctx.now - timedelta(days=days)
        affected = [u for u in tenant.active_users if u.last_login_at and u.last_login_at < cutoff]
        if not affected:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(affected), 'account')} unused for over {days} days",
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="m365.users",
                        pointer="/m365.users",
                        summary=f"{plural(len(affected), 'enabled account')} last signed in more than {days} days ago.",
                        observed_values={"dormant": len(affected), "days": days},
                    )
                ],
            )
        ]


@register
class M365BlockedAccountsRetained(M365Rule):
    rule_id = "M365-STA-003"
    check_family = CheckFamily.STALE_ACCOUNTS
    title = "Blocked accounts still in the directory"
    impact = 2
    exposure = 3
    remediation_key = "m365.accounts.review_blocked"
    framework_refs = ("PR.AA-01",)
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        affected = [u for u in tenant.users if u.suspended]
        if not affected:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(affected), 'blocked account')} still present in the directory",
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="m365.users",
                        pointer="/m365.users",
                        summary=(
                            f"{plural(len(affected), 'account')} {'is' if len(affected) == 1 else 'are'} blocked from "
                            "signing in but not deleted. Blocking keeps the mailbox, the OneDrive files, their "
                            "sharing links and any access granted to outside applications."
                        ),
                        observed_values={"blocked": len(affected)},
                    )
                ],
                confidence=Confidence.MEDIUM,
            )
        ]


# -- 4. Applications acting on their own ----------------------------------------------------


@register
class M365AppOnlyDataAccess(M365Rule):
    """Microsoft-only: an app that can read every mailbox or file, by itself."""

    rule_id = "M365-SVC-001"
    check_family = CheckFamily.SERVICE_ACCOUNT_PRIVILEGE
    title = "Applications that can read every user's data on their own"
    impact = 5
    exposure = 3
    remediation_key = "m365.apps.review_app_only"
    framework_refs = ("PR.AA-05", "PR.DS-01")
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        by_app: dict[str, list] = {}
        for g in tenant.app_only_grants:
            if not g.is_assessor and g.tier in _DATA_TIERS:
                by_app.setdefault(g.app_id, []).append(g)
        findings = []
        for app_id, grants in sorted(by_app.items(), key=lambda kv: kv[1][0].app_name):
            name = grants[0].app_name
            perms = sorted({g.permission for g in grants})
            admin_equivalent = any(g.tier == ScopeTier.ADMIN_EQUIVALENT for g in grants)
            findings.append(
                self.make_finding(
                    tenant,
                    ctx,
                    title=f"'{name}' can read every user's data without anyone signed in",
                    entities=[_app(app_id, name)],
                    evidence=[
                        Evidence(
                            collector="m365.graph_permissions",
                            pointer=f"/m365.graph_permissions/application_grants[app={app_id}]",
                            summary=(
                                f"'{name}' holds {', '.join(perms)} as an application permission: it applies to "
                                "every user in the organization, works at any time, and needs no one to sign in. "
                                "Anyone holding this app's secret or certificate has the same access."
                            ),
                            observed_values={"permissions": ", ".join(perms)},
                        )
                    ],
                    discriminator=app_id,
                    exposure=4 if admin_equivalent else None,
                )
            )
        return findings


@register
class M365LongLivedAppSecrets(M365Rule):
    """Microsoft-only: password-like app secrets valid for over a year."""

    rule_id = "M365-SVC-002"
    check_family = CheckFamily.SERVICE_ACCOUNT_PRIVILEGE
    title = "Application secrets valid for more than a year"
    impact = 3
    exposure = 3
    remediation_key = "m365.apps.shorten_secrets"
    framework_refs = ("PR.AA-01",)
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        limit = int(ctx.threshold("app_secret_max_days", 365))
        affected = [
            c
            for c in tenant.app_credentials
            if c.kind == "secret" and not c.is_assessor and (c.lifetime_days or 0) > limit
        ]
        if not affected:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(affected), 'application secret')} valid for more than {limit // 30} months",
                entities=[_app(c.app_id, c.app_name) for c in affected],
                evidence=[
                    Evidence(
                        collector="m365.applications",
                        pointer=f"/m365.applications[appId={c.app_id}]/secrets",
                        summary=(
                            f"'{c.app_name}' has a secret valid for {c.lifetime_days} days, until "
                            f"{_day(c.expires)}. A secret is a password for the application; a long-lived "
                            "one that leaks keeps working for years."
                        ),
                        observed_values={"lifetime_days": c.lifetime_days or 0},
                    )
                    for c in affected
                ],
            )
        ]


# -- 5. Sharing ---------------------------------------------------------------------------


@register
class M365PublicFiles(M365Rule):
    rule_id = "M365-SHR-001"
    check_family = CheckFamily.EXTERNAL_SHARING
    title = "Files reachable by anyone with the link"
    impact = 4
    exposure = 5
    remediation_key = "m365.sharing.close_anyone_links"
    framework_refs = ("PR.DS-01", "PR.AA-05")
    default_effort_hours = 3.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        public = [r for r in tenant.resources if r.publicly_accessible]
        if not public:
            return []
        departed = [r for r in public if r.settings.get("owner_enabled") is False]
        evidence = [
            Evidence(
                collector="m365.public_files",
                pointer="/m365.public_files",
                summary=(
                    f"{plural(len(public), 'OneDrive item')} can be opened by anyone with the link, "
                    "with no sign-in."
                ),
                observed_values={"public_items": len(public)},
            )
        ] + [
            Evidence(
                collector="m365.public_files",
                pointer=f"/m365.public_files[id={r.id}]",
                summary=(
                    f"'{r.name}' belongs to {r.owner_id}, whose account is blocked, and its public link "
                    "still works."
                ),
                observed_values={"owner_blocked": True},
            )
            for r in departed
        ]
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(public), 'OneDrive item')} shared with anyone who has the link",
                entities=[
                    AffectedEntity(id=r.id, kind="file", label=r.name, is_privileged=False) for r in public
                ],
                evidence=evidence,
            )
        ]


@register
class M365AnyoneLinksAllowed(M365Rule):
    rule_id = "M365-SHR-002"
    check_family = CheckFamily.EXTERNAL_SHARING
    title = "Organization allows 'Anyone' sharing links"
    impact = 3
    exposure = 4
    remediation_key = "m365.sharing.restrict_org_setting"
    framework_refs = ("PR.DS-01",)
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        raw = _require_policy(tenant)
        capability = raw.get("sharing_capability")
        if capability is None:
            raise RuleNotAssessable(
                "The organization's SharePoint and OneDrive sharing setting could not be read."
            )
        if capability != "externalUserAndGuestSharing":
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title="Staff can share files with 'Anyone', no sign-in needed",
                entities=[_setting("SharePoint and OneDrive sharing")],
                evidence=[
                    Evidence(
                        collector="m365.sharepoint_settings",
                        pointer="/m365.sharepoint_settings/sharingCapability",
                        summary=(
                            "The organization-wide sharing setting is at its most permissive level ('Anyone'), "
                            "so any staff member can create links that work for people outside the "
                            "organization without signing in."
                        ),
                        observed_values={"sharingCapability": capability},
                    )
                ],
            )
        ]


@register
class M365GuestInvitesUnrestricted(M365Rule):
    rule_id = "M365-SHR-003"
    check_family = CheckFamily.EXTERNAL_SHARING
    title = "Anyone can invite outside guests"
    impact = 2
    exposure = 4
    remediation_key = "m365.sharing.restrict_guest_invites"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        raw = _require_policy(tenant)
        if raw.get("allow_invites_from") != "everyone":
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    "Anyone, including existing guests, can invite outside people into the organization "
                    f"({plural(len(tenant.guests), 'guest')} present)"
                ),
                entities=[_setting("Guest invitations")] + [entity_from_identity(g) for g in tenant.guests],
                evidence=[
                    Evidence(
                        collector="m365.policies",
                        pointer="/m365.policies/authorization/allow_invites_from",
                        summary=(
                            "Guest invitations are open to everyone, including guests themselves, so outside "
                            "accounts can be added without an administrator knowing."
                        ),
                        observed_values={"allowInvitesFrom": "everyone", "guests": len(tenant.guests)},
                    )
                ],
            )
        ]


# -- 6. Logging ------------------------------------------------------------------------------


@register
class M365LogsUnavailable(M365Rule):
    rule_id = "M365-LOG-001"
    check_family = CheckFamily.LOGGING_READINESS
    title = "Activity logs not available for investigation"
    impact = 3
    exposure = 3
    remediation_key = "m365.logging.enable_logs"
    framework_refs = ("DE.AE-03", "PR.PS-04")
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        missing = [s for s in tenant.audit_streams if not s.available]
        if not missing:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(missing), 'activity log')} could not be read",
                entities=[_setting(s.name.replace("_", " ")) for s in missing],
                evidence=[
                    Evidence(
                        collector="m365.audit_readiness",
                        pointer=f"/m365.audit_readiness/streams/{s.name}",
                        summary=f"The {s.name.replace('_', ' ')} log was unavailable ({s.reason}).",
                        observed_values={"available": False},
                    )
                    for s in missing
                ],
            )
        ]


# -- 7. Outside applications with access granted by people --------------------------------------


@register
class M365BroadDelegatedApps(M365Rule):
    rule_id = "M365-OAU-001"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Applications that can read staff mail or files"
    impact = 4
    exposure = 3
    remediation_key = "m365.apps.review_delegated"
    framework_refs = ("PR.AA-05", "PR.DS-01")
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        by_app: dict[str, list] = {}
        for g in tenant.grants:
            if not g.is_first_party and g.max_tier in _DATA_TIERS:
                by_app.setdefault(g.client_id, []).append(g)
        people = {u.id: u for u in tenant.identities}
        findings = []
        for app_id, grants in sorted(by_app.items(), key=lambda kv: kv[1][0].app_name or ""):
            name = grants[0].app_name or app_id
            everyone = any(g.user_id == "*" for g in grants)
            holders = [people[g.user_id] for g in grants if g.user_id in people]
            broad = sorted({s.scope for g in grants for s in g.scopes if s.tier in _DATA_TIERS})
            standing = sorted(
                people[g.user_id].label
                for g in grants
                if g.user_id in people and "offline_access" in g.scope_strings
            )
            who = (
                "every user (approved by an administrator)"
                if everyone
                else plural(len(holders), "person", "people")
            )
            findings.append(
                self.make_finding(
                    tenant,
                    ctx,
                    title=f"'{name}' can read the mail or files of {who}",
                    entities=[entity_from_identity(u) for u in holders] or [_app(app_id, name)],
                    evidence=[
                        Evidence(
                            collector="m365.graph_permissions",
                            pointer=f"/m365.graph_permissions/delegated_grants[clientId={app_id}]",
                            summary=(
                                f"'{name}' was given {', '.join(broad)} by {who}. That access continues after "
                                "password changes and after the person stops using the app."
                                + (
                                    f" For {', '.join(standing)} it can also stay signed in on its own "
                                    "(offline access), so it can read at any time."
                                    if standing
                                    else ""
                                )
                            ),
                            observed_values={"permissions": ", ".join(broad), "users": len(holders)},
                        )
                    ],
                    discriminator=app_id,
                )
            )
        return findings


@register
class M365GrantsHeldByBlockedUsers(M365Rule):
    rule_id = "M365-OAU-002"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Application access still held by blocked accounts"
    impact = 4
    exposure = 4
    remediation_key = "m365.apps.revoke_departed"
    framework_refs = ("PR.AA-01", "PR.AA-05")
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        people = {u.id: u for u in tenant.identities}
        held = [
            (people[g.user_id], g)
            for g in tenant.grants
            if g.user_id in people
            and people[g.user_id].suspended
            and g.max_tier.weight > ScopeTier.SIGN_IN_ONLY.weight
        ]
        if not held:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len({u.id for u, _ in held}), 'blocked account')} still {'gives' if len(held) == 1 else 'give'} outside applications access",
                entities=[entity_from_identity(u) for u in {u.id: u for u, _ in held}.values()],
                evidence=[
                    Evidence(
                        collector="m365.graph_permissions",
                        pointer=f"/m365.graph_permissions/delegated_grants[principalId={u.id}]",
                        summary=(
                            f"{u.label} is blocked, but '{g.app_name}' still holds "
                            f"{', '.join(s.scope for s in g.scopes if s.tier.weight > ScopeTier.SIGN_IN_ONLY.weight)} "
                            "over that account. Blocking sign-in does not withdraw access already given to apps."
                        ),
                        observed_values={"app": g.app_name or g.client_id},
                    )
                    for u, g in held
                ],
            )
        ]


@register
class M365RiskyConsentPolicy(M365Rule):
    """Microsoft-only: ordinary users may approve mail or file access."""

    rule_id = "M365-OAU-003"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Staff can give applications access to their mail or files without an administrator"
    impact = 4
    exposure = 3
    remediation_key = "m365.apps.tighten_consent"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        from icp.normalizers.microsoft import tier_of

        raw = _require_policy(tenant)
        users_may_consent = any(
            "ManagePermissionGrantsForSelf" in p for p in raw.get("consent_policies", [])
        )
        risky = sorted(p for p in raw.get("low_impact_permissions", []) if tier_of(p) in _DATA_TIERS)
        if not users_may_consent or not risky:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"Any staff member can give an application access to their {', '.join(risky)} data",
                entities=[_setting("User consent settings")],
                evidence=[
                    Evidence(
                        collector="m365.graph_permissions",
                        pointer="/m365.graph_permissions/low_impact_classifications",
                        summary=(
                            f"Users may approve applications themselves, and {', '.join(risky)} is classified as "
                            "'low impact', so any staff member can let an application read their mail or files "
                            "without an administrator seeing the request."
                        ),
                        observed_values={"low_impact": ", ".join(raw.get("low_impact_permissions", []))},
                    )
                ],
            )
        ]


@register
class M365UsersCanRegisterApps(M365Rule):
    rule_id = "M365-OAU-004"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Any user can register new applications"
    impact = 2
    exposure = 3
    remediation_key = "m365.apps.restrict_registration"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 0.25

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        raw = _require_policy(tenant)
        if raw.get("users_can_register_apps") is not True:
            return []
        return [
            self.make_finding(
                tenant,
                ctx,
                title="Any staff member can create new applications in the organization",
                entities=[_setting("User settings: app registrations")],
                evidence=[
                    Evidence(
                        collector="m365.policies",
                        pointer="/m365.policies/authorization/users_can_register_apps",
                        summary=(
                            "Every user can register applications. An application created inside the "
                            "organization counts as trusted when other staff are asked to approve it."
                        ),
                        observed_values={"allowedToCreateApps": True},
                    )
                ],
            )
        ]
