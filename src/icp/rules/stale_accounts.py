"""Check family 3 -- stale and orphaned accounts.

Two distinct problems that look similar in a user list: accounts that were never
really used, and accounts belonging to people who left. The second is the one
that costs money and creates risk simultaneously, because a suspended account
often still holds live application tokens (see check family 7).
"""

from __future__ import annotations

from icp.models.enums import CheckFamily, Confidence
from icp.models.finding import Evidence, Finding
from icp.normalizers.base import NormalizedTenant
from icp.rules.base import Rule, RuleContext, entity_from_identity, plural, register


@register
class DormantAccounts(Rule):
    rule_id = "GWS-STA-001"
    check_family = CheckFamily.STALE_ACCOUNTS
    title = "Active accounts with no recent sign-in"

    impact = 3
    exposure = 3

    remediation_key = "accounts.suspend_dormant"
    framework_refs = ("PR.AA-01", "ID.AM-05")
    default_effort_hours = 2.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        days = int(ctx.threshold("dormant_user_days", 90))
        cutoff = ctx.now.timestamp() - days * 86400

        affected = [
            u
            for u in tenant.active_users
            if u.last_login_at is not None and u.last_login_at.timestamp() < cutoff
        ]
        if not affected:
            return []

        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(affected), 'active account')} with no sign-in for {days}+ days",
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="google.users",
                        pointer=f"/google.users/{u.id}/lastLoginTime",
                        summary=(
                            f"{u.label} last signed in "
                            f"{u.last_login_at.date().isoformat() if u.last_login_at else 'unknown'}."
                        ),
                        observed_values={
                            "last_login": u.last_login_at.isoformat() if u.last_login_at else None,
                            "threshold_days": days,
                        },
                    )
                    for u in affected
                ],
                confidence=Confidence.HIGH,
            )
        ]


@register
class NeverUsedAccounts(Rule):
    rule_id = "GWS-STA-002"
    check_family = CheckFamily.STALE_ACCOUNTS
    title = "Accounts that have never been signed into"

    impact = 3
    exposure = 3

    remediation_key = "accounts.remove_never_used"
    framework_refs = ("PR.AA-01",)
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        min_age_days = int(ctx.threshold("never_used_min_age_days", 30))
        cutoff = ctx.now.timestamp() - min_age_days * 86400

        # An account created yesterday that has not been used is not a finding;
        # it is a new starter. The age floor is what keeps this rule from
        # generating noise during onboarding.
        affected = [
            u
            for u in tenant.active_users
            if u.last_login_at is None and u.created_at is not None and u.created_at.timestamp() < cutoff
        ]
        if not affected:
            return []

        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{plural(len(affected), 'account')} created over {min_age_days} days ago "
                    "and never signed into"
                ),
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="google.users",
                        pointer=f"/google.users/{u.id}",
                        summary=(
                            f"{u.label} was created "
                            + (u.created_at.date().isoformat() if u.created_at else "unknown")
                            + " and has no recorded sign-in."
                        ),
                        observed_values={
                            "created": u.created_at.isoformat() if u.created_at else None,
                            "last_login": None,
                        },
                    )
                    for u in affected
                ],
            )
        ]


@register
class SuspendedAccountsRetained(Rule):
    rule_id = "GWS-STA-003"
    check_family = CheckFamily.STALE_ACCOUNTS
    title = "Suspended accounts retained without a documented reason"

    impact = 2
    exposure = 2

    remediation_key = "accounts.review_suspended"
    framework_refs = ("PR.AA-01",)
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        suspended = [u for u in tenant.users if u.suspended and not u.archived]
        if not suspended:
            return []

        # Suspension is often correct (litigation hold, seasonal staff). This is
        # reported as a review item, not a defect -- and the severity says so.
        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(suspended), 'suspended account')} still present in the directory",
                entities=[entity_from_identity(u) for u in suspended],
                evidence=[
                    Evidence(
                        collector="google.users",
                        pointer="/google.users",
                        summary=(
                            f"{len(suspended)} accounts are suspended but not archived or deleted. "
                            "Suspension retains the account's data and any tokens it holds."
                        ),
                        observed_values={"suspended_count": len(suspended)},
                    )
                ],
                confidence=Confidence.MEDIUM,
            )
        ]
