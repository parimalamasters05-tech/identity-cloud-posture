"""Prioritization.

The report's priority action plan is sorted by severity first, then by risk
reduced per hour within each severity. Within a band, cheap high-value fixes
come first, which is what actually gets done in the week after delivery.

Pure risk-per-hour (the first version) let any 30-minute medium jump two
criticals: the manual top-10 review ranked "sign-in warning off" above "an app
can administer every user". No skeptical reader accepts that, and the brief is
explicit that when the review disagrees, the rubric is wrong. Severity is the
claim the report makes about urgency; the ordering must never contradict it.
"""

from __future__ import annotations

from dataclasses import dataclass

from icp.models.enums import Severity
from icp.models.finding import Finding

#: Floor on effort so a near-zero estimate cannot produce an infinite ratio.
_MIN_EFFORT_HOURS = 0.25


@dataclass(frozen=True)
class RankedFinding:
    finding: Finding
    rank: int
    risk_per_hour: float

    #: Other findings fixed by the same action. The action plan is a list of
    #: things to do, not a list of things that are wrong, so five findings that
    #: share one remediation are one item with a note, not five items.
    also_resolves: tuple[Finding, ...] = ()

    @property
    def covers(self) -> int:
        return 1 + len(self.also_resolves)


def risk_per_hour(finding: Finding) -> float:
    return round(finding.risk_score / max(finding.effort_hours, _MIN_EFFORT_HOURS), 2)


def _sort_key(finding: Finding) -> tuple[int, float, int, str]:
    """Severity band, then risk per hour, then entity count, then finding_id.

    The last term matters more than it looks: without it, two equal findings can
    swap places between runs and the delta report shows movement that did not
    happen.
    """
    return (-finding.severity.rank, -risk_per_hour(finding), -finding.entity_count, finding.finding_id)


def rank(
    findings: list[Finding],
    *,
    limit: int | None = None,
    dedupe_by_action: bool = False,
) -> list[RankedFinding]:
    """Order by severity, then risk-reduced-per-hour.

    With `dedupe_by_action`, findings sharing a remediation key collapse into a
    single entry led by the highest-scoring one. That is the right shape for the
    action plan: "review applications that can read all mail" is one afternoon's
    work whether it covers one application or nine, and listing it nine times
    pushes genuinely different work off the page.
    """
    ordered = sorted(findings, key=_sort_key)

    if dedupe_by_action:
        leaders: dict[str, Finding] = {}
        followers: dict[str, list[Finding]] = {}
        for finding in ordered:
            key = finding.remediation_key
            if key in leaders:
                followers.setdefault(key, []).append(finding)
            else:
                leaders[key] = finding
        ordered = sorted(leaders.values(), key=_sort_key)
        grouped = {k: tuple(v) for k, v in followers.items()}
    else:
        grouped = {}

    if limit is not None:
        ordered = ordered[:limit]

    return [
        RankedFinding(
            finding=f,
            rank=i + 1,
            risk_per_hour=risk_per_hour(f),
            also_resolves=grouped.get(f.remediation_key, ()),
        )
        for i, f in enumerate(ordered)
    ]


def posture_rating(findings: list[Finding]) -> tuple[str, str]:
    """A single headline rating for the executive summary.

    Deliberately blunt and threshold-driven rather than a computed 0-100 score.
    A director needs a word, and a word that cannot be argued into a better one
    by shaving a point off a weighting.
    """
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)

    if critical >= 1:
        return ("Action required", "One or more critical gaps need attention now.")
    if high >= 5:
        return ("Weak", "Several high-severity gaps compound each other.")
    if high >= 1:
        return ("Needs improvement", "No critical gaps, but meaningful high-severity issues remain.")
    return ("Reasonable", "No critical or high-severity gaps found in the areas assessed.")
