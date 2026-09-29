"""Check family 7 -- third-party OAuth grants. The differentiator.

Most posture tools check MFA and admin counts. Almost none surface what
employees have already consented to hand over. A single user granting a defunct
startup's app read access to all mail is a standing data-exfiltration path that
survives password rotation, survives MFA enrollment, and appears on no
compliance checklist -- because the consent was legitimate and nobody ever
revisited it.

Findings here are aggregated per application, not per user. "Forty-one people
authorized things" is not actionable; "this one transcription app can read every
mailbox it was given, and two of its users left last year" is.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from icp.models.enums import Assessability, CheckFamily, Confidence, ScopeTier
from icp.models.finding import AffectedEntity, Evidence, Finding
from icp.models.identity import OAuthGrant
from icp.normalizers.base import NormalizedTenant
from icp.rules.base import Rule, RuleContext, RuleNotAssessable, plural, register

#: Tiers that mean "this app can read or change everything the user can".
BROAD_TIERS = frozenset({ScopeTier.FULL_DATA_READ, ScopeTier.FULL_DATA_WRITE, ScopeTier.ADMIN_EQUIVALENT})


def _entities(tenant: NormalizedTenant, grants: Iterable[OAuthGrant]) -> list[AffectedEntity]:
    out = []
    for grant in grants:
        identity = tenant.identity_by_id(grant.user_id)
        out.append(
            AffectedEntity(
                id=grant.user_id,
                kind="user",
                label=grant.user_email or grant.user_id,
                is_privileged=bool(identity and identity.is_privileged),
            )
        )
    return out


def third_party(grants: Iterable[OAuthGrant]) -> list[OAuthGrant]:
    """Grants to outside vendors. Google's own tools are reported by GWS-SVC-003."""
    return [g for g in grants if not g.is_first_party]


def _group_by_app(grants: Iterable[OAuthGrant]) -> dict[str, list[OAuthGrant]]:
    grouped: dict[str, list[OAuthGrant]] = defaultdict(list)
    for grant in grants:
        grouped[grant.client_id].append(grant)
    return dict(sorted(grouped.items()))


@register
class GrantsHeldBySuspendedUsers(Rule):
    """The single most reliable "I had no idea" finding in the catalogue.

    Suspending an account blocks interactive sign-in. It does not revoke tokens
    the account previously issued, so an application holding a refresh token can
    keep reading that mailbox after the person has left the organization.
    """

    rule_id = "GWS-OAU-001"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Applications still authorized by departed staff"

    impact = 5
    exposure = 5

    remediation_key = "oauth.revoke_suspended_user_grants"
    framework_refs = ("PR.AA-01", "PR.AA-05", "ID.AM-05")
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        suspended_ids = {u.id for u in tenant.users if u.suspended or u.archived}
        affected = [g for g in tenant.grants if g.user_id in suspended_ids]
        if not affected:
            return []

        apps = _group_by_app(affected)

        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{plural(len(apps), 'application')} still authorized by "
                    f"{plural(len({g.user_id for g in affected}), 'suspended or archived account')}"
                ),
                entities=_entities(tenant, affected),
                evidence=[
                    Evidence(
                        collector="google.oauth_tokens",
                        pointer=f"/google.oauth_tokens/grants[userId={g.user_id}]",
                        summary=(
                            f"'{g.app_name or g.client_id}' still holds "
                            f"{plural(len(g.scopes), 'permission')} granted by {g.user_email}, whose "
                            "account is suspended or archived. Suspending an account does not "
                            "take back access it already gave to applications."
                        ),
                        observed_values={
                            "app": g.app_name or g.client_id,
                            "user": g.user_email,
                            "max_scope_tier": str(g.max_tier),
                        },
                    )
                    for g in affected[:25]
                ],
            )
        ]


@register
class BroadScopeApplications(Rule):
    """Applications that can read everything, ranked by users affected."""

    rule_id = "GWS-OAU-002"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Applications with full mailbox or Drive access"

    impact = 4
    exposure = 4

    remediation_key = "oauth.review_broad_scope_apps"
    framework_refs = ("PR.AA-05", "PR.DS-01")
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        broad = [g for g in third_party(tenant.grants) if g.max_tier in BROAD_TIERS]
        if not broad:
            return []

        findings: list[Finding] = []
        for client_id, grants in _group_by_app(broad).items():
            app_name = grants[0].app_name or client_id
            users = len({g.user_id for g in grants})
            scopes = sorted({s.scope for g in grants for s in g.scopes if s.tier in BROAD_TIERS})

            # Exposure scales with how much of the organization is exposed.
            share = users / max(len(tenant.active_users), 1)
            exposure = 5 if share >= 0.5 else 4 if share >= 0.2 else 3

            findings.append(
                self.make_finding(
                    tenant,
                    ctx,
                    title=(
                        f"'{app_name}' can "
                        + (
                            "read and change"
                            if any(
                                g.max_tier in (ScopeTier.FULL_DATA_WRITE, ScopeTier.ADMIN_EQUIVALENT)
                                for g in grants
                            )
                            else "read"
                        )
                        + f" organization data for {plural(users, 'user')}"
                    ),
                    entities=_entities(tenant, grants),
                    discriminator=client_id,
                    exposure=exposure,
                    evidence=[
                        Evidence(
                            collector="google.oauth_tokens",
                            pointer=f"/google.oauth_tokens/grants[clientId={client_id}]",
                            summary=(
                                f"'{app_name}' holds {plural(len(scopes), 'broad permission')} "
                                f"over the data of {plural(users, 'person', 'people')}, "
                                f"{round(share * 100)}% of active staff."
                            ),
                            observed_values={
                                "client_id": client_id,
                                "users_affected": users,
                                "staff_share_pct": round(share * 100, 1),
                                "broad_scopes": ", ".join(scopes[:4]),
                            },
                        )
                    ],
                )
            )
        return findings


@register
class UnverifiedApplications(Rule):
    """Apps not registered with Google ("anonymous"). A strong shadow-IT signal.

    Named for the brief's "unverified apps" item, but what Google exposes is
    registration, not its verification review -- and the finding says so.
    """

    rule_id = "GWS-OAU-003"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Unregistered applications holding access"

    impact = 4
    exposure = 3

    remediation_key = "oauth.investigate_unverified_apps"
    framework_refs = ("ID.AM-05", "PR.AA-05")
    default_effort_hours = 1.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        anonymous = [g for g in third_party(tenant.grants) if g.is_anonymous_app]
        if not anonymous:
            return []

        findings: list[Finding] = []
        for client_id, grants in _group_by_app(anonymous).items():
            users = len({g.user_id for g in grants})
            findings.append(
                self.make_finding(
                    tenant,
                    ctx,
                    title=f"Unregistered application ({client_id[:24]}) authorized by {plural(users, 'user')}",
                    entities=_entities(tenant, grants),
                    discriminator=client_id,
                    evidence=[
                        Evidence(
                            collector="google.oauth_tokens",
                            pointer=f"/google.oauth_tokens/grants[clientId={client_id}]",
                            summary=(
                                "Google reports this client as anonymous: it is not registered "
                                "with Google, so it carries no publisher identity at all. (This is "
                                "not Google's app-verification status, which the API does not "
                                "expose.) Confirm with the IT contact whether it is a known "
                                "internal script before revoking."
                            ),
                            observed_values={
                                "client_id": client_id,
                                "users_affected": users,
                                "max_scope_tier": str(grants[0].max_tier),
                            },
                        )
                    ],
                    confidence=Confidence.HIGH,
                )
            )
        return findings


@register
class SingleUserBroadScopeApps(Rule):
    """One or two users, wide access: the classic shadow-IT shape."""

    rule_id = "GWS-OAU-004"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Broad-access applications used by only one or two people"

    impact = 3
    exposure = 3

    remediation_key = "oauth.review_shadow_it"
    framework_refs = ("ID.AM-05",)
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        threshold = int(ctx.threshold("shadow_it_user_ceiling", 2))
        candidates = [g for g in third_party(tenant.grants) if g.max_tier in BROAD_TIERS]

        findings: list[Finding] = []
        for client_id, grants in _group_by_app(candidates).items():
            users = {g.user_id for g in grants}
            if len(users) > threshold:
                continue
            app_name = grants[0].app_name or client_id
            findings.append(
                self.make_finding(
                    tenant,
                    ctx,
                    title=f"'{app_name}' holds broad access but is used by only {plural(len(users), 'person', 'people')}",
                    entities=_entities(tenant, grants),
                    discriminator=client_id,
                    evidence=[
                        Evidence(
                            collector="google.oauth_tokens",
                            pointer=f"/google.oauth_tokens/grants[clientId={client_id}]",
                            summary=(
                                f"'{app_name}' was connected by {plural(len(users), 'person', 'people')} "
                                "with wide access to organization data. Tools adopted by one person and "
                                "never reviewed are the most common source of forgotten access."
                            ),
                            observed_values={
                                "client_id": client_id,
                                "users_affected": len(users),
                                "max_scope_tier": str(grants[0].max_tier),
                            },
                        )
                    ],
                    confidence=Confidence.MEDIUM,
                )
            )
        return findings


@register
class DormantGrants(Rule):
    """Standing access nobody uses.

    Every grant in the token listing is standing access until revoked. One the
    audit log shows no use of for months is an open door nobody walks through
    -- which is precisely why nobody notices it.

    The previous version inferred dormancy from missing data: Google's token
    listing has no last-use field, so every broad app was "dormant". Now the
    rule fires only on what the token audit log actually shows, and reports
    "not assessed" when the log cannot show usage at all.
    """

    rule_id = "GWS-OAU-005"
    check_family = CheckFamily.OAUTH_GRANTS
    title = "Applications holding access with no recorded use"
    requires_collectors = ("google.token_activity",)

    impact = 3
    exposure = 4

    remediation_key = "oauth.revoke_dormant_grants"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        days = int(ctx.threshold("dormant_grant_days", 90))
        cutoff = ctx.now - timedelta(days=days)
        log = tenant.token_log

        if log is None:
            raise RuleNotAssessable(
                "The token audit log was not collected in this snapshot, so application "
                "usage could not be checked.",
                assessability=Assessability.NOT_ASSESSABLE_ERROR,
            )
        if not log.activity_recorded:
            raise RuleNotAssessable(
                "Google's token audit log for this organization records when applications were "
                "authorized and revoked, but not when they were used, so unused access cannot be "
                "told apart from used access. Recording of usage events may depend on the "
                "Workspace edition.",
                assessability=Assessability.NOT_ASSESSABLE_LICENSE,
            )
        if log.covered_since > cutoff:
            raise RuleNotAssessable(
                f"The token audit log could only be read back to "
                f"{log.covered_since.date().isoformat()}, less than the {days} days needed to "
                "call an application unused.",
                assessability=Assessability.NOT_ASSESSABLE_ERROR,
            )

        active_ids = {u.id for u in tenant.active_users}
        dormant = [
            g
            for g in third_party(tenant.grants)
            # Suspended accounts' grants are GWS-OAU-001's, and more urgent.
            if g.user_id in active_ids
            # Sign-in-only grants reach no data; "unused access" is meaningless there.
            and g.max_tier != ScopeTier.SIGN_IN_ONLY
            and (g.last_used_at is None or g.last_used_at < cutoff)
            # Consent inside the window is recent, used or not.
            and (g.last_authorized_at is None or g.last_authorized_at < cutoff)
        ]
        if not dormant:
            return []

        apps = _group_by_app(dormant)
        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{plural(len(apps), 'application')} holding access with no recorded use "
                    f"in {days}+ days"
                ),
                entities=_entities(tenant, dormant),
                evidence=[
                    Evidence(
                        collector="google.token_activity",
                        pointer=f"/google.token_activity/apps[client_id={client_id}]",
                        summary=(
                            f"'{grants[0].app_name or client_id}' is authorized by "
                            f"{plural(len(grants), 'account')} and the token audit log shows no use "
                            f"of it since {log.covered_since.date().isoformat()}"
                            + (
                                f" (last used {max(g.last_used_at for g in grants if g.last_used_at).date()})."
                                if any(g.last_used_at for g in grants)
                                else "."
                            )
                        ),
                        observed_values={
                            "client_id": client_id,
                            "users": ", ".join(sorted(g.user_email or g.user_id for g in grants)),
                            "log_covers_since": log.covered_since.date().isoformat(),
                            "threshold_days": days,
                        },
                    )
                    for client_id, grants in apps.items()
                ],
                confidence=Confidence.HIGH,
            )
        ]
