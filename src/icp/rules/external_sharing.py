"""Check family 5 -- external sharing and public exposure.

Only files whose permissions already make them reachable without authentication
are reported. The tool never opens them; the finding is about the permission,
not the content, which keeps the engagement inside its data-minimization
promise.
"""

from __future__ import annotations

from icp.models.enums import CheckFamily, Confidence
from icp.models.finding import AffectedEntity, Evidence, Finding
from icp.normalizers.base import NormalizedTenant
from icp.rules.base import Rule, RuleContext, RuleNotAssessable, plural, register


@register
class PubliclyAccessibleFiles(Rule):
    rule_id = "GWS-SHR-001"
    check_family = CheckFamily.EXTERNAL_SHARING
    title = "Files reachable by anyone with the link"

    impact = 4
    exposure = 5

    remediation_key = "sharing.restrict_public_links"
    framework_refs = ("PR.DS-01", "PR.AA-05")
    default_effort_hours = 3.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        public = [r for r in tenant.resources if r.publicly_accessible]
        if not public:
            return []

        entities = [AffectedEntity(id=r.id, kind="file", label=r.name, is_privileged=False) for r in public]
        from_log = [r for r in public if r.settings.get("source") == "audit_log"]

        evidence = [
            Evidence(
                collector="google.public_drive_items",
                pointer="/google.public_drive_items",
                summary=(
                    f"{plural(len(public), 'Drive item')} can be opened by anyone with the "
                    "link. Link sharing outlasts staff departures and needs no sign-in."
                ),
                observed_values={
                    "public_item_count": len(public),
                    "example": public[0].name,
                    "owners": ", ".join(sorted({r.owner_id for r in public if r.owner_id})[:3]),
                },
            )
        ]
        # Files whose owner could not be searched were found in the audit log:
        # said plainly, because they were not read directly.
        evidence += [
            Evidence(
                collector="google.public_drive_items",
                pointer=f"/google.public_drive_items[id={r.id}]",
                summary=(
                    f"'{r.name}' belongs to {r.owner_id}, whose account is suspended or could not "
                    "be searched, so the file itself could not be checked. Google's Drive audit log "
                    f"shows it was made public on {str(r.settings.get('made_public_at'))[:10]} and "
                    "records no change back since."
                ),
                observed_values={"source": "Drive audit log", "owner": r.owner_id},
            )
            for r in from_log
        ]

        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(public), 'Drive item')} shared with anyone who has the link",
                entities=entities,
                evidence=evidence,
                # Read from the log, not the file: the last recorded state.
                confidence=Confidence.HIGH if from_log else Confidence.CONFIRMED,
            )
        ]


@register
class OrgWideSharingUnrestricted(Rule):
    rule_id = "GWS-SHR-002"
    check_family = CheckFamily.EXTERNAL_SHARING
    title = "External sharing permitted without warnings"

    impact = 3
    exposure = 4

    remediation_key = "sharing.enable_external_warnings"
    framework_refs = ("PR.DS-01",)
    default_effort_hours = 0.5

    requires_collectors = ("google.workspace_policies",)

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        policy = tenant.policy
        if (
            policy is None
            or policy.external_sharing_allowed is None
            or policy.external_sharing_warning_enabled is None
        ):
            raise RuleNotAssessable(
                "Drive's external-sharing policy was not read in this assessment, so whether "
                "staff see a warning before sharing outside the organization was not checked. "
                "Reading it needs the Cloud Identity Policy API (read-only)."
            )
        if not policy.external_sharing_allowed:
            return []
        if policy.external_sharing_warning_enabled:
            return []

        unwarned = (policy.raw.get("drive_sharing") or {}).get("unwarned") or []
        return [
            self.make_finding(
                tenant,
                ctx,
                title="External sharing is allowed with no warning prompt for staff",
                entities=[AffectedEntity(id=policy.domain, kind="domain", label=policy.domain)],
                evidence=[
                    Evidence(
                        collector="google.workspace_policies",
                        pointer=(
                            "/google.workspace_policies/policies[setting_type=drive_and_docs.external_sharing,"
                            f"org_unit={p['org_unit']},group={p['group']}]"
                        ),
                        summary=(
                            f"Drive sharing for {_where(p)} is set to {p['mode']} with the "
                            "'warn when sharing outside' option off. The warning is a low-cost "
                            "control that catches accidental external shares as they happen."
                        ),
                        observed_values={
                            "external_sharing_mode": p["mode"],
                            "warning_enabled": False,
                            "org_unit": p["org_unit"] or None,
                            "group": p["group"] or None,
                        },
                    )
                    for p in unwarned
                ],
                # Only reached when both settings were actually read.
                confidence=Confidence.CONFIRMED,
            )
        ]


def _where(policy: dict[str, str]) -> str:
    if policy.get("group"):
        return f"members of group {policy['group']}"
    if policy.get("org_unit"):
        return f"organizational unit {policy['org_unit']}"
    return "the organization"
