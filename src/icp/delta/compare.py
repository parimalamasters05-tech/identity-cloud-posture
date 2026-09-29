"""Snapshot-to-snapshot comparison -- the retainer product.

A one-time report is stale in a quarter. A re-run showing what changed is a
different and more valuable product, and because everything downstream reads
only snapshots, it costs almost nothing to build.

The whole thing rests on deterministic finding IDs. If an ID moves when a
finding's score changes, every quarter shows spurious churn and the trend line
becomes noise. `tests/rules/test_finding_id_stability.py` guards that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from icp.models.enums import FindingStatus, Severity
from icp.models.finding import Finding


@dataclass(frozen=True)
class MembershipChange:
    """Who joined or left a finding that is open in both assessments."""

    added: tuple[str, ...]
    removed: tuple[str, ...]
    previous_count: int
    current_count: int


@dataclass
class DeltaReport:
    previous_snapshot_id: str
    current_snapshot_id: str
    previous_at: datetime
    current_at: datetime

    resolved: list[Finding] = field(default_factory=list)
    new: list[Finding] = field(default_factory=list)
    persisting: list[Finding] = field(default_factory=list)
    improved: list[Finding] = field(default_factory=list)
    regressed: list[Finding] = field(default_factory=list)
    #: finding_id -> membership change, for every finding open in both.
    changes: dict[str, MembershipChange] = field(default_factory=dict)
    #: finding_id -> the previous assessment's version, for "was X, now Y".
    previous_scores: dict[str, float] = field(default_factory=dict)

    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # -- headline numbers ------------------------------------------------------

    @property
    def open_in_both(self) -> list[Finding]:
        return self.persisting + self.improved + self.regressed

    @property
    def net_change(self) -> int:
        return len(self.new) - len(self.resolved)

    def risk_totals(self) -> dict[str, float]:
        # Each side scored as it was then: an improved finding counts its old
        # score before and its new score after.
        previous = sum(f.risk_score for f in self.resolved) + sum(
            self.previous_scores.get(f.finding_id, f.risk_score) for f in self.open_in_both
        )
        current = sum(f.risk_score for f in self.new + self.open_in_both)
        return {
            "previous": round(previous, 2),
            "current": round(current, 2),
            "change": round(current - previous, 2),
            "change_pct": round(100 * (current - previous) / previous, 1) if previous else 0.0,
        }

    def summary(self) -> dict[str, Any]:
        return {
            "resolved": len(self.resolved),
            "new": len(self.new),
            "persisting": len(self.persisting),
            "improved": len(self.improved),
            "regressed": len(self.regressed),
            "accounts_fixed_in_open_findings": sum(len(c.removed) for c in self.changes.values()),
            "accounts_added_to_open_findings": sum(len(c.added) for c in self.changes.values()),
            "net_change": self.net_change,
            "risk": self.risk_totals(),
            "resolved_critical_high": sum(
                1 for f in self.resolved if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ),
            "window_days": (self.current_at - self.previous_at).days,
        }


def compare(
    previous: list[Finding],
    current: list[Finding],
    *,
    previous_snapshot_id: str = "",
    current_snapshot_id: str = "",
    previous_at: datetime | None = None,
    current_at: datetime | None = None,
) -> DeltaReport:
    """Diff two finding sets by finding ID.

    A finding present in both is *regressed* if its severity rose or it gained
    accounts -- "this got worse since last time" is a materially different
    conversation from "this is still open". It is *improved* if it lost
    accounts or severity without gaining any, and *persisting* otherwise. Who
    joined and left is recorded either way: "pat.dunne fixed theirs, two new
    starters were added without 2SV" is the quarterly conversation.
    """
    previous_index = {f.finding_id: f for f in previous}
    current_index = {f.finding_id: f for f in current}

    report = DeltaReport(
        previous_snapshot_id=previous_snapshot_id,
        current_snapshot_id=current_snapshot_id,
        previous_at=previous_at or datetime.now(UTC),
        current_at=current_at or datetime.now(UTC),
    )

    for finding_id, finding in current_index.items():
        earlier = previous_index.get(finding_id)
        if earlier is None:
            report.new.append(finding.model_copy(update={"status": FindingStatus.NEW}))
            continue

        # Carry the original first_seen forward: "open since March" is one of the
        # most persuasive lines in a quarterly walkthrough.
        carried = finding.model_copy(update={"first_seen": earlier.first_seen})

        before = {e.key(): e.label for e in earlier.affected_entities}
        after = {e.key(): e.label for e in finding.affected_entities}
        change = MembershipChange(
            added=tuple(sorted(after[k] for k in after.keys() - before.keys())),
            removed=tuple(sorted(before[k] for k in before.keys() - after.keys())),
            previous_count=earlier.entity_count,
            current_count=finding.entity_count,
        )
        report.changes[finding_id] = change
        report.previous_scores[finding_id] = earlier.risk_score

        if finding.severity.rank > earlier.severity.rank or change.current_count > change.previous_count:
            report.regressed.append(carried.model_copy(update={"status": FindingStatus.REGRESSED}))
        elif finding.severity.rank < earlier.severity.rank or change.current_count < change.previous_count:
            report.improved.append(carried.model_copy(update={"status": FindingStatus.IMPROVED}))
        else:
            report.persisting.append(carried.model_copy(update={"status": FindingStatus.PERSISTING}))

    for finding_id, finding in previous_index.items():
        if finding_id not in current_index:
            report.resolved.append(finding.model_copy(update={"status": FindingStatus.RESOLVED}))

    return report


def trend_line(history: list[tuple[datetime, list[Finding]]]) -> list[dict[str, Any]]:
    """Posture over successive assessments, for the retainer's trend chart."""
    points = []
    for at, findings in sorted(history, key=lambda item: item[0]):
        actionable = [f for f in findings if f.severity != Severity.INFO]
        points.append(
            {
                "at": at.isoformat(),
                "total_findings": len(actionable),
                "total_risk": round(sum(f.risk_score for f in actionable), 2),
                "critical": sum(1 for f in actionable if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in actionable if f.severity == Severity.HIGH),
            }
        )
    return points
