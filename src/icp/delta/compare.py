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

#: Coverage notes: not problems, but the record of what an assessment could not see.
_NOT_ASSESSED_FAMILY = "ICP-COVERAGE-001"
_NOT_ASSESSED_RULE = "ICP-COVERAGE-002"
_PARTLY_ASSESSED = "ICP-COVERAGE-003"
_COVERAGE = (_NOT_ASSESSED_FAMILY, _NOT_ASSESSED_RULE, _PARTLY_ASSESSED)


@dataclass(frozen=True)
class Visibility:
    """What one assessment could not fully see, read from its coverage notes.

    Without this, a finding that vanished because its data could not be read
    (a permission withdrawn, a collector failing) was reported as resolved,
    and its risk counted as removed (review, 27 Oct 2026).
    """

    families: frozenset[str] = frozenset()  # not assessed at all
    rules: frozenset[str] = frozenset()  # one rule not assessed
    #: family -> the accounts not read (None: not known who)
    partial: dict[str, frozenset[str] | None] = field(default_factory=dict)

    @classmethod
    def of(cls, findings: list[Finding]) -> Visibility:
        families: set[str] = set()
        rules: set[str] = set()
        partial: dict[str, frozenset[str] | None] = {}
        for f in findings:
            if f.rule_id == _NOT_ASSESSED_FAMILY:
                families.add(str(f.check_family))
            elif f.rule_id == _NOT_ASSESSED_RULE:
                rules |= {e.id for e in f.affected_entities}
            elif f.rule_id == _PARTLY_ASSESSED:
                observed = f.evidence[0].observed_values if f.evidence else {}
                missed = [e.id for e in f.affected_entities if e.kind == "user"]
                for family in str(observed.get("families") or f.check_family).split(","):
                    partial[family] = frozenset(missed) if missed else None
        return cls(frozenset(families), frozenset(rules), partial)

    def missed(self, finding: Finding) -> frozenset[str] | None:
        """Accounts of this finding's area that were not read (None: unknown)."""
        return self.partial.get(str(finding.check_family), frozenset())

    def reassessed(self, finding: Finding) -> bool:
        """Was this finding's check, and everyone it named, fully assessed?"""
        if str(finding.check_family) in self.families or finding.rule_id in self.rules:
            return False
        missed = self.missed(finding)
        return missed is not None and not ({e.id for e in finding.affected_entities} & missed)


@dataclass(frozen=True)
class MembershipChange:
    """Who joined or left a finding that is open in both assessments."""

    added: tuple[str, ...]
    removed: tuple[str, ...]
    previous_count: int
    current_count: int
    #: Gone from the finding, but their data was not read this time: not fixed,
    #: just not seen. Not in `removed`.
    unconfirmed: tuple[str, ...] = ()


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
    #: Open before, absent now, but its check or the accounts it named were not
    #: fully assessed this time: not shown to be fixed. Never counted as resolved.
    not_revalidated: list[Finding] = field(default_factory=list)
    #: Absent before only because its check could not be assessed then: not new.
    first_assessed: list[Finding] = field(default_factory=list)
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
        # score before and its new score after. Findings not comparable across
        # the two (not rechecked, or checked for the first time) are left out
        # of both sides: a drop in visibility is not a drop in risk.
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
            "not_revalidated": len(self.not_revalidated),
            "first_assessed": len(self.first_assessed),
            "accounts_fixed_in_open_findings": sum(len(c.removed) for c in self.changes.values()),
            "accounts_not_rechecked_in_open_findings": sum(
                len(c.unconfirmed) for c in self.changes.values()
            ),
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

    Each side's coverage notes (passed in with its findings) say what it could
    not see. A finding gone from a check, or an area, that was not fully
    assessed this time is *not rechecked*, never resolved; one appearing where
    the earlier review could not look is *first assessed*, not new. An account
    gone from an open finding whose data was not read is unconfirmed, not fixed.
    """
    previous_seen, current_seen = Visibility.of(previous), Visibility.of(current)
    previous_index = {f.finding_id: f for f in previous if f.rule_id not in _COVERAGE}
    current_index = {f.finding_id: f for f in current if f.rule_id not in _COVERAGE}

    report = DeltaReport(
        previous_snapshot_id=previous_snapshot_id,
        current_snapshot_id=current_snapshot_id,
        previous_at=previous_at or datetime.now(UTC),
        current_at=current_at or datetime.now(UTC),
    )

    for finding_id, finding in current_index.items():
        earlier = previous_index.get(finding_id)
        if earlier is None:
            if previous_seen.reassessed(finding):
                report.new.append(finding.model_copy(update={"status": FindingStatus.NEW}))
            else:
                report.first_assessed.append(
                    finding.model_copy(update={"status": FindingStatus.FIRST_ASSESSED})
                )
            continue

        # Carry the original first_seen forward: "open since March" is one of the
        # most persuasive lines in a quarterly walkthrough.
        carried = finding.model_copy(update={"first_seen": earlier.first_seen})

        before = {e.key(): e for e in earlier.affected_entities}
        after = {e.key(): e for e in finding.affected_entities}
        gone = [before[k] for k in before.keys() - after.keys()]
        missed = current_seen.missed(finding)
        unseen = [e for e in gone if missed is None or e.id in missed]
        change = MembershipChange(
            added=tuple(sorted(after[k].label for k in after.keys() - before.keys())),
            removed=tuple(sorted(e.label for e in gone if e not in unseen)),
            previous_count=earlier.entity_count,
            current_count=finding.entity_count,
            unconfirmed=tuple(sorted(e.label for e in unseen)),
        )
        report.changes[finding_id] = change
        report.previous_scores[finding_id] = earlier.risk_score

        if finding.severity.rank > earlier.severity.rank or change.added:
            report.regressed.append(carried.model_copy(update={"status": FindingStatus.REGRESSED}))
        elif finding.severity.rank < earlier.severity.rank or change.removed:
            report.improved.append(carried.model_copy(update={"status": FindingStatus.IMPROVED}))
        else:
            report.persisting.append(carried.model_copy(update={"status": FindingStatus.PERSISTING}))

    for finding_id, finding in previous_index.items():
        if finding_id in current_index:
            continue
        if current_seen.reassessed(finding):
            report.resolved.append(finding.model_copy(update={"status": FindingStatus.RESOLVED}))
        else:
            report.not_revalidated.append(
                finding.model_copy(update={"status": FindingStatus.NOT_REVALIDATED})
            )

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
