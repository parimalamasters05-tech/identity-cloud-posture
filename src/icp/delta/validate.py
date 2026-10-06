"""Validate a delta against the snapshots it came from.

`icp delta` compares two findings files. That is only as trustworthy as the
files: a findings file could be stale, hand-edited, or produced by a different
version of the rules. This re-derives both sides from the raw snapshots and
checks that nothing but the tenant changed:

1. each snapshot, re-assessed as of its collection time, gives exactly its saved findings (IDs,
   rules, severities, affected entities, scores);
2. the delta of the re-derived findings equals the delta of the saved files;
3. both collections were read-only.

Offline: snapshots and findings files only. First run live on the dev tenant,
29 Sep 2026, against a real remediation (developer-tool logins removed).
"""

from __future__ import annotations

from dataclasses import dataclass

from icp.delta.compare import compare
from icp.models.finding import Finding
from icp.models.snapshot import Snapshot
from icp.normalizers import normalize_snapshot as normalize
from icp.rules import assess

_READ_METHODS = frozenset({"GET", "HEAD"})


@dataclass(frozen=True)
class Check:
    label: str
    passed: bool
    detail: str = ""


def _fingerprint(finding: Finding) -> tuple:
    """What must not change when the same snapshot is assessed again.

    Timestamps (first_seen, last_seen) are excluded: they are stamped at
    assessment time by design.
    """
    return (
        finding.finding_id,
        finding.rule_id,
        str(finding.severity),
        tuple(sorted(e.id for e in finding.affected_entities)),
        round(finding.risk_score, 2),
    )


def rederive(snapshot: Snapshot) -> list[Finding]:
    return list(assess(normalize(snapshot), now=snapshot.collected_at).findings)


def validate(
    before: Snapshot,
    after: Snapshot,
    saved_before: list[Finding],
    saved_after: list[Finding],
) -> tuple[list[Check], dict]:
    """Returns the checks and the re-derived delta summary."""
    checks: list[Check] = []
    rederived = {}

    for label, snapshot, saved in (("previous", before, saved_before), ("current", after, saved_after)):
        fresh = rederive(snapshot)
        rederived[label] = fresh
        a, b = sorted(map(_fingerprint, fresh)), sorted(map(_fingerprint, saved))
        differ = sorted({f[0] for f in set(a) ^ set(b)})
        checks.append(
            Check(
                f"{label} snapshot re-assessed gives its saved findings ({len(b)})",
                a == b,
                "" if a == b else f"differ: {', '.join(differ)}",
            )
        )

    def summary(previous: list[Finding], current: list[Finding]) -> dict:
        return compare(
            previous,
            current,
            previous_snapshot_id=before.snapshot_id,
            current_snapshot_id=after.snapshot_id,
        ).summary()

    saved_delta = summary(saved_before, saved_after)
    fresh_delta = summary(rederived["previous"], rederived["current"])
    checks.append(
        Check(
            "delta from the snapshots equals delta from the saved files",
            saved_delta == fresh_delta,
            "" if saved_delta == fresh_delta else f"saved {saved_delta} vs re-derived {fresh_delta}",
        )
    )

    for label, snapshot in (("previous", before), ("current", after)):
        methods = sorted({c.method for c in snapshot.api_calls})
        checks.append(
            Check(
                f"{label} collection was read-only",
                set(methods) <= _READ_METHODS,
                ", ".join(methods) or "no calls recorded",
            )
        )

    return checks, fresh_delta
