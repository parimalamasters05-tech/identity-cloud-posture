"""Check family 6 -- logging and audit readiness.

The question is not "do you have logs" but "if something happened six weeks ago,
could you reconstruct it". A missing or empty admin audit stream means the
answer is no, and that is worth saying plainly in a report a board will read.
"""

from __future__ import annotations

from icp.models.enums import CheckFamily, Confidence
from icp.models.finding import AffectedEntity, Evidence, Finding
from icp.normalizers.base import NormalizedTenant
from icp.rules.base import Rule, RuleContext, plural, register

#: Streams that must exist for an incident to be investigable at all.
_ESSENTIAL_STREAMS = ("admin", "login", "token")


@register
class MissingAuditStreams(Rule):
    rule_id = "GWS-LOG-001"
    check_family = CheckFamily.LOGGING_READINESS
    title = "Audit streams unavailable for investigation"

    impact = 4
    exposure = 3

    remediation_key = "logging.enable_audit_streams"
    framework_refs = ("DE.AE-03", "PR.PS-04")
    default_effort_hours = 2.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        by_name = {s.name: s for s in tenant.audit_streams}
        missing = [name for name in _ESSENTIAL_STREAMS if name in by_name and not by_name[name].available]
        if not missing:
            return []

        return [
            self.make_finding(
                tenant,
                ctx,
                title=f"{plural(len(missing), 'essential audit stream')} could not be read",
                entities=[
                    AffectedEntity(id=name, kind="audit_stream", label=f"{name} activity log")
                    for name in missing
                ],
                evidence=[
                    Evidence(
                        collector="google.audit_readiness",
                        pointer=f"/google.audit_readiness/streams/{name}",
                        summary=(
                            f"The {name} activity stream returned no data. Without it, "
                            "administrative changes and sign-in activity cannot be reconstructed "
                            "after an incident."
                        ),
                        observed_values={"stream": name, "available": False},
                    )
                    for name in missing
                ],
            )
        ]


@register
class SilentAuditStreams(Rule):
    rule_id = "GWS-LOG-002"
    check_family = CheckFamily.LOGGING_READINESS
    title = "Audit streams available but empty"

    impact = 3
    exposure = 3

    remediation_key = "logging.verify_audit_coverage"
    framework_refs = ("DE.AE-03",)
    default_effort_hours = 1.0

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        silent = [
            s
            for s in tenant.audit_streams
            if s.available and s.event_count_sampled == 0 and s.name in _ESSENTIAL_STREAMS
        ]
        if not silent:
            return []

        window = silent[0].probe_window_days

        # An empty admin log over 30 days is usually real (small org, few
        # changes) but occasionally indicates a retention or licensing problem.
        # Reported at medium confidence with the ambiguity stated.
        return [
            self.make_finding(
                tenant,
                ctx,
                title=(
                    f"{plural(len(silent), 'audit stream')} recorded no events in the last {window} days"
                ),
                entities=[
                    AffectedEntity(id=s.name, kind="audit_stream", label=f"{s.name} activity log")
                    for s in silent
                ],
                evidence=[
                    Evidence(
                        collector="google.audit_readiness",
                        pointer=f"/google.audit_readiness/streams/{s.name}",
                        summary=(
                            f"The {s.name} stream is reachable but returned zero events over a "
                            f"{window}-day window. This is expected in a quiet tenant and "
                            "unexpected in an active one; confirm with the IT contact."
                        ),
                        observed_values={"stream": s.name, "events_sampled": 0, "window_days": window},
                    )
                    for s in silent
                ],
                confidence=Confidence.MEDIUM,
            )
        ]
