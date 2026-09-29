"""Check family 4 -- over-privileged non-human identities.

In Google Workspace the non-human identity surface is mostly OAuth clients:
integrations, scripts, and automation holding delegated authority. This family
looks at the *privilege* those identities hold; family 7 looks at the
population of grants as a whole. The split matters because the fixes differ --
here you narrow a scope, there you revoke an app.
"""

from __future__ import annotations

from collections import defaultdict

from icp.models.enums import CheckFamily, Confidence, ScopeTier
from icp.models.finding import AffectedEntity, Evidence, Finding
from icp.normalizers.base import NormalizedTenant
from icp.rules.base import Rule, RuleContext, plural, register
from icp.rules.oauth_grant_risk import BROAD_TIERS, third_party

#: Tier names are internal vocabulary; evidence sentences are read by people.
_TIER_WORDS = {
    ScopeTier.ADMIN_EQUIVALENT: "administrator-level",
    ScopeTier.FULL_DATA_WRITE: "read-and-change",
    ScopeTier.FULL_DATA_READ: "read-everything",
}


@register
class AdminEquivalentApplications(Rule):
    rule_id = "GWS-SVC-001"
    check_family = CheckFamily.SERVICE_ACCOUNT_PRIVILEGE
    title = "Applications holding administrator-equivalent authority"

    impact = 5
    exposure = 4

    remediation_key = "apps.revoke_admin_equivalent"
    framework_refs = ("PR.AA-05", "ID.AM-05")
    default_effort_hours = 2.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        by_app: dict[str, list] = defaultdict(list)
        for grant in third_party(tenant.grants):
            if grant.max_tier == ScopeTier.ADMIN_EQUIVALENT:
                by_app[grant.client_id].append(grant)

        findings: list[Finding] = []
        for client_id, grants in sorted(by_app.items()):
            app_name = grants[0].app_name or client_id
            scopes = sorted(
                {s.scope for g in grants for s in g.scopes if s.tier == ScopeTier.ADMIN_EQUIVALENT}
            )
            entities = [
                AffectedEntity(
                    id=g.user_id,
                    kind="user",
                    label=g.user_email or g.user_id,
                    is_privileged=bool(
                        (identity := tenant.identity_by_id(g.user_id)) and identity.is_privileged
                    ),
                )
                for g in grants
            ]

            findings.append(
                self.make_finding(
                    tenant,
                    ctx,
                    title=f"'{app_name}' holds administrator-equivalent access",
                    entities=entities,
                    discriminator=client_id,
                    evidence=[
                        Evidence(
                            collector="google.oauth_tokens",
                            pointer=f"/google.oauth_tokens/grants[clientId={client_id}]",
                            summary=(
                                f"'{app_name}' holds {plural(len(scopes), 'administrator-level permission')}, "
                                f"granted by {plural(len(grants), 'person', 'people')}. With these it "
                                "can act across the whole organization without asking anyone again."
                            ),
                            observed_values={
                                "client_id": client_id,
                                "users_affected": len(grants),
                                "admin_scopes": ", ".join(scopes[:4]),
                            },
                        )
                    ],
                )
            )
        return findings


@register
class ApplicationsHeldOnlyByPrivilegedUsers(Rule):
    rule_id = "GWS-SVC-002"
    check_family = CheckFamily.SERVICE_ACCOUNT_PRIVILEGE
    title = "Broad-scope applications authorized by administrators"

    impact = 4
    exposure = 3

    remediation_key = "apps.review_admin_authorized"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 1.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        broad = {ScopeTier.FULL_DATA_READ, ScopeTier.FULL_DATA_WRITE, ScopeTier.ADMIN_EQUIVALENT}
        privileged_ids = {u.id for u in tenant.admins}

        by_app: dict[str, list] = defaultdict(list)
        for grant in third_party(tenant.grants):
            if grant.user_id in privileged_ids and grant.max_tier in broad:
                by_app[grant.client_id].append(grant)

        findings: list[Finding] = []
        for client_id, grants in sorted(by_app.items()):
            app_name = grants[0].app_name or client_id
            entities = [
                AffectedEntity(
                    id=g.user_id, kind="user", label=g.user_email or g.user_id, is_privileged=True
                )
                for g in grants
            ]
            findings.append(
                self.make_finding(
                    tenant,
                    ctx,
                    title=f"'{app_name}' was authorized by an administrator with broad access",
                    entities=entities,
                    discriminator=client_id,
                    evidence=[
                        Evidence(
                            collector="google.oauth_tokens",
                            pointer=f"/google.oauth_tokens/grants[clientId={client_id}]",
                            summary=(
                                f"An administrator granted '{app_name}' broad data access. "
                                "An application authorized by an admin inherits the reach of that "
                                "account's mailbox and files, which is wider than for other staff."
                            ),
                            observed_values={
                                "client_id": client_id,
                                "admin_grantors": len(grants),
                                "max_scope_tier": str(grants[0].max_tier),
                            },
                        )
                    ],
                    confidence=Confidence.HIGH,
                )
            )
        return findings


@register
class DeveloperToolLogins(Rule):
    """Google's own command-line tools, signed in with broad access.

    Not vendor risk, so kept out of the third-party rules -- listing Google's
    gcloud CLI as a "third-party application" is the fastest way to lose a
    skeptical IT contact. But the login is a real, long-lived credential on
    someone's computer, and saying nothing would be a false pass.
    """

    rule_id = "GWS-SVC-003"
    check_family = CheckFamily.SERVICE_ACCOUNT_PRIVILEGE
    title = "Google developer tools signed in with broad access"

    impact = 4
    exposure = 2

    remediation_key = "apps.revoke_developer_tool_logins"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 0.5

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        active_ids = {u.id for u in tenant.active_users}
        grants = [
            g
            for g in tenant.grants
            # Chrome and Android sign-ins are first-party too, and normal; only
            # a developer-tool login is a credential worth a finding.
            if g.first_party_kind == "developer_tool"
            and g.user_id in active_ids
            and g.max_tier in BROAD_TIERS
        ]
        if not grants:
            return []

        users = sorted({g.user_id for g in grants})
        tools = sorted({g.app_name or g.client_id for g in grants})
        entities = []
        for user_id in users:
            identity = tenant.identity_by_id(user_id)
            email = next(g.user_email for g in grants if g.user_id == user_id)
            entities.append(
                AffectedEntity(
                    id=user_id,
                    kind="user",
                    label=email or user_id,
                    is_privileged=bool(identity and identity.is_privileged),
                )
            )

        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{plural(len(users), 'account')} signed in to Google's developer tools "
                    f"({', '.join(tools)}) with broad access"
                ),
                entities=entities,
                evidence=[
                    Evidence(
                        collector="google.oauth_tokens",
                        pointer=f"/google.oauth_tokens/grants[clientId={g.client_id}]",
                        summary=(
                            f"{g.user_email} is signed in to '{g.app_name or g.client_id}', a Google "
                            "tool rather than an outside vendor, with "
                            f"{_TIER_WORDS.get(g.max_tier, 'broad')} access. The login stays valid "
                            "on that computer until it is revoked."
                        ),
                        observed_values={
                            "client_id": g.client_id,
                            "user": g.user_email,
                            "max_scope_tier": str(g.max_tier),
                        },
                    )
                    for g in grants
                ],
                confidence=Confidence.HIGH,
            )
        ]
