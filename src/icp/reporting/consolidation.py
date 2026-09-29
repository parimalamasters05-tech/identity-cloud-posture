"""One report entry per application, not one per rule that noticed it.

Five rules look at OAuth applications from different angles -- broad data
access, administrator-level scopes, authorized by an admin, used by one person,
unidentified vendor. Against a real tenant one admin connecting four apps
produced fourteen findings, and a director read "3 critical, 10 high" for what
was really four decisions about four apps.

This happens only at the presentation layer. The findings JSON, finding IDs and
delta reports still carry every rule's finding individually, so nothing about
traceability or quarter-on-quarter comparison changes.
"""

from __future__ import annotations

from dataclasses import dataclass

from icp.models.finding import Finding

#: Rules that emit exactly one finding per application, keyed by client ID.
#: Explicit rather than inferred: a rule that reports several apps in one
#: finding (GWS-OAU-005, GWS-SVC-003) must never be folded into one of them.
PER_APPLICATION_RULES = frozenset(
    {"GWS-SVC-001", "GWS-SVC-002", "GWS-OAU-002", "GWS-OAU-003", "GWS-OAU-004"}
)


@dataclass(frozen=True)
class ReportEntry:
    finding: Finding
    #: Other findings about the same application, shown as extra reasons.
    related: tuple[Finding, ...] = ()


def _application_key(finding: Finding) -> str | None:
    if finding.rule_id not in PER_APPLICATION_RULES:
        return None
    for evidence in finding.evidence:
        client_id = evidence.observed_values.get("client_id")
        if client_id:
            return f"{finding.platform}:{client_id}"
    return None


def _lead_key(finding: Finding) -> tuple[int, float, str]:
    # Worst severity leads, so the entry's badge is never milder than a reason
    # listed beneath it. finding_id breaks ties so the choice is stable per run.
    return (-finding.severity.rank, -finding.risk_score, finding.finding_id)


def consolidate(findings: list[Finding]) -> list[ReportEntry]:
    """Group per-application findings; everything else passes through alone."""
    groups: dict[str, list[Finding]] = {}
    entries: list[ReportEntry] = []

    for finding in findings:
        key = _application_key(finding)
        if key is None:
            entries.append(ReportEntry(finding=finding))
        else:
            groups.setdefault(key, []).append(finding)

    for members in groups.values():
        lead, *rest = sorted(members, key=_lead_key)
        entries.append(ReportEntry(finding=lead, related=tuple(rest)))

    return entries
