"""Check family 2 -- administrative role sprawl.

Super-admin counts in small organizations are almost always too high, usually
for historical reasons nobody remembers. The thresholds here scale with
headcount rather than being fixed, because "four super-admins" means something
very different in a 12-person nonprofit than in a 400-person one.
"""

from __future__ import annotations

from icp.models.enums import CheckFamily, Confidence
from icp.models.finding import Evidence, Finding
from icp.normalizers.base import NormalizedTenant
from icp.rules.base import Rule, RuleContext, entity_from_identity, plural, register

#: Recommended ceiling regardless of size: enough for continuity, few enough to review.
_ABSOLUTE_CEILING = 4
#: Above this share of staff, super-admin has stopped being an exception.
_RATIO_CEILING = 0.10
#: Never recommend fewer than this: a named primary and a break-glass account,
#: which is exactly what the remediation for this finding tells the client to
#: keep. Without the floor, 10% of a 9-person organization is 0.9, so even a
#: single super-admin fired -- in the market this tool is built for.
_MINIMUM_ALLOWED = 2


@register
class ExcessiveSuperAdmins(Rule):
    rule_id = "GWS-ADM-001"
    check_family = CheckFamily.ADMIN_ROLE_SPRAWL
    title = "More super-administrators than the organization needs"

    impact = 4
    exposure = 4

    remediation_key = "admin.reduce_super_admins"
    framework_refs = ("PR.AA-05",)
    default_effort_hours = 2.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        supers = [u for u in tenant.super_admins if not u.suspended]
        active = len(tenant.active_users) or 1
        ceiling = ctx.threshold("super_admin_ceiling", _ABSOLUTE_CEILING)
        ratio_ceiling = ctx.threshold("super_admin_ratio", _RATIO_CEILING)
        floor = ctx.threshold("super_admin_minimum", _MINIMUM_ALLOWED)

        # The lower of the two ceilings, but never below the continuity floor.
        allowed = int(max(floor, min(ceiling, int(active * ratio_ceiling))))
        ratio = len(supers) / active
        if len(supers) <= allowed:
            return []

        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{plural(len(supers), 'super-administrator account')} for "
                    f"{plural(active, 'active user')} ({round(ratio * 100, 1)}% of staff)"
                ),
                entities=[entity_from_identity(u) for u in supers],
                evidence=[
                    Evidence(
                        collector="google.role_assignments",
                        pointer="/google.role_assignments",
                        summary=(
                            f"{len(supers)} accounts hold super-admin, against a recommended "
                            f"maximum of {allowed} for {plural(active, 'active user')}: "
                            f"{round(ratio_ceiling * 100)}% of staff or {ceiling}, whichever is "
                            f"lower, but never fewer than {int(floor)} (a named primary and a "
                            "break-glass account)."
                        ),
                        observed_values={
                            "super_admin_count": len(supers),
                            "active_users": active,
                            "ratio_pct": round(ratio * 100, 1),
                            "recommended_maximum": allowed,
                        },
                    )
                ],
            )
        ]


@register
class DormantAdministrators(Rule):
    rule_id = "GWS-ADM-002"
    check_family = CheckFamily.ADMIN_ROLE_SPRAWL
    title = "Administrator accounts not used recently"

    impact = 4
    exposure = 3

    remediation_key = "admin.remove_dormant_admin_rights"
    framework_refs = ("PR.AA-05", "ID.AM-05")
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        days = int(ctx.threshold("dormant_admin_days", 45))
        cutoff = ctx.now.timestamp() - days * 86400

        # "Never signed in" only proves dormancy once the account is older than
        # the window. Without this floor, an admin created last week is reported
        # as "unused for 45+ days", which is false and the first thing a client
        # checks.
        affected = [
            u
            for u in tenant.admins
            if not u.suspended
            and (
                (u.last_login_at is not None and u.last_login_at.timestamp() < cutoff)
                or (u.last_login_at is None and (u.created_at is None or u.created_at.timestamp() < cutoff))
            )
        ]
        if not affected:
            return []

        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{plural(len(affected), 'administrator account')} unused for {days}+ days "
                    "but still holding full privileges"
                ),
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="google.users",
                        pointer=f"/google.users/{u.id}/lastLoginTime",
                        summary=(
                            f"{u.label} holds admin privileges; "
                            + (
                                f"last signed in {u.last_login_at.date().isoformat()}."
                                if u.last_login_at
                                else "has never signed in"
                                + (
                                    f" since the account was created on {u.created_at.date().isoformat()}."
                                    if u.created_at
                                    else "."
                                )
                            )
                        ),
                        observed_values={
                            "last_login": u.last_login_at.isoformat() if u.last_login_at else None,
                            "created": u.created_at.isoformat() if u.created_at else None,
                            "threshold_days": days,
                        },
                    )
                    for u in affected
                ],
                confidence=Confidence.HIGH,
            )
        ]
