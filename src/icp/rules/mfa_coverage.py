"""Check family 1 -- MFA coverage and method strength.

Split into three rules rather than one, because they have genuinely different
severities and different fixes. Lumping "the CFO has no MFA" together with
"twelve staff have SMS instead of a security key" produces a finding nobody can
act on.
"""

from __future__ import annotations

from icp.models.enums import CheckFamily, Confidence
from icp.models.finding import Evidence, Finding
from icp.normalizers.base import NormalizedTenant
from icp.rules.base import Rule, RuleContext, entity_from_identity, plural, register


def _report_as_of(report_date: str | None) -> str:
    """' Based on Google's report for 27 September 2026, ...' or '' when unknown."""
    if not report_date:
        return ""
    from datetime import date

    try:
        day = date.fromisoformat(report_date)
    except ValueError:
        return ""
    return (
        f" Based on Google's security report for {day.day} {day:%B %Y}, the latest Google had "
        "published. Google releases this report one to three days late, so a security key or "
        "passkey added after that date is not reflected."
    )


@register
class AdminsWithoutMfa(Rule):
    rule_id = "GWS-MFA-001"
    check_family = CheckFamily.MFA_COVERAGE
    title = "Administrator accounts without two-step verification"

    # Highest impact in the catalogue: a super-admin without a second factor is a
    # single credential away from full tenant compromise.
    impact = 5
    exposure = 5

    remediation_key = "mfa.enforce_admins"
    framework_refs = ("PR.AA-03", "PR.AA-05")
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        affected = [u for u in tenant.admins if not u.suspended and not u.mfa_enrolled]
        if not affected:
            return []

        return [
            self.make_finding(
                tenant,
                ctx,
                title=(f"{plural(len(affected), 'administrator account')} with no second factor enrolled"),
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="google.users",
                        pointer=f"/google.users/{u.id}/isEnrolledIn2Sv",
                        summary=f"{u.label} is an administrator and has not enrolled in two-step verification.",
                        observed_values={
                            "isEnrolledIn2Sv": False,
                            "isSuperAdmin": u.is_super_admin,
                            "roles": ", ".join(u.admin_roles) or "(directly assigned)",
                        },
                    )
                    for u in affected
                ],
            )
        ]


@register
class UsersWithoutMfa(Rule):
    rule_id = "GWS-MFA-002"
    check_family = CheckFamily.MFA_COVERAGE
    title = "Standard accounts without two-step verification"

    impact = 4
    exposure = 4

    remediation_key = "mfa.enforce_all_users"
    framework_refs = ("PR.AA-03",)
    default_effort_hours = 3.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        affected = [u for u in tenant.active_users if not u.is_privileged and not u.mfa_enrolled]
        if not affected:
            return []

        total = len(tenant.active_users) or 1
        coverage_pct = round(100 * (total - len(affected)) / total, 1)

        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{len(affected)} of {total} active accounts have no second factor "
                    f"({coverage_pct}% coverage)"
                ),
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="google.users",
                        pointer="/google.users",
                        summary=(
                            f"{plural(len(affected), 'active staff account')} (not administrators) "
                            f"{'has' if len(affected) == 1 else 'have'} not enrolled in two-step "
                            "verification."
                        ),
                        observed_values={
                            "accounts_without_2sv": len(affected),
                            "active_accounts": total,
                            "coverage_pct": coverage_pct,
                        },
                    )
                ],
            )
        ]


@register
class AdminsWithoutPhishingResistantMfa(Rule):
    rule_id = "GWS-MFA-003"
    check_family = CheckFamily.MFA_COVERAGE
    title = "Administrators without phishing-resistant second factors"

    impact = 4
    exposure = 3

    remediation_key = "mfa.security_keys_for_admins"
    framework_refs = ("PR.AA-03",)
    default_effort_hours = 4.0

    # Without the usage report every enrolled admin looks key-less, so running
    # this rule on a degraded collector would report a false positive.
    requires_collectors = ("google.mfa",)

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        affected = [
            u
            for u in tenant.admins
            if not u.suspended
            and u.mfa_enrolled
            # Missing from the provider's method report: unknown, not weak.
            # Named in a coverage note by the normalizer instead.
            and u.mfa_method_known
            and not u.has_phishing_resistant_mfa
        ]
        if not affected:
            return []

        # Google reports security key and passkey counts but not which weaker
        # factor is in use, so "not phishing-resistant" is read from both counts
        # being zero rather than observed directly.
        #
        # The report trails the snapshot by days. Found on the dev tenant: a
        # passkey added the morning of the run still showed as none, with
        # nothing in the report to say why. The date is stated on every line.
        as_of = _report_as_of(tenant.mfa_report_date)
        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{plural(len(affected), 'administrator account')} using a second factor "
                    "that can be phished"
                ),
                entities=[entity_from_identity(u) for u in affected],
                evidence=[
                    Evidence(
                        collector="google.mfa",
                        pointer=f"/google.mfa/entries/{u.id}/num_security_keys",
                        summary=(
                            f"{u.label} has two-step verification but no security key or passkey "
                            "registered, so the second step is a text message, an authenticator "
                            "code or a phone prompt, all of which a fake sign-in page can pass on "
                            "to an attacker in real time." + as_of
                        ),
                        observed_values={
                            "num_security_keys": 0,
                            "num_passkeys_enrolled": 0,
                            "two_step_enrolled": True,
                            "report_date": tenant.mfa_report_date or "not stated",
                        },
                    )
                    for u in affected
                ],
                confidence=Confidence.HIGH,
            )
        ]
