"""Progress since an earlier review of the same platform.

The delta command prints this comparison for the assessor; this puts it in the
report, for the client. It compares two readings and says what changed. It does
not say why: a finding can close because someone fixed it, or because the
account it named was deleted for another reason.
"""

from __future__ import annotations

from typing import Any

from icp.delta.compare import compare
from icp.normalizers.base import NormalizedTenant
from icp.reporting.platform_text import for_platform
from icp.rules.engine import AssessmentResult

#: Order and wording of the outcome groups. Worse news first within "still open".
_GROUPS = (
    ("resolved", "Resolved"),
    ("improved", "Improved"),
    ("regressed", "Worse"),
    ("new", "New"),
    ("persisting", "Unchanged"),
    # Neither better nor worse: the two reviews could not see the same things.
    ("not_revalidated", "Not rechecked"),
    ("first_assessed", "First checked"),
)


def _names(labels: tuple[str, ...], limit: int = 3) -> str:
    shown = ", ".join(labels[:limit])
    return shown + (f" and {len(labels) - limit} more" if len(labels) > limit else "")


def build(
    previous: tuple[NormalizedTenant, AssessmentResult],
    current: tuple[NormalizedTenant, AssessmentResult],
) -> dict[str, Any]:
    """One platform's before-and-after, as the template needs it."""
    (before_tenant, before_result), (after_tenant, after_result) = previous, current
    if before_tenant.platform != after_tenant.platform:
        raise ValueError("Progress compares two snapshots of the same platform")
    if before_tenant.snapshot.collected_at >= after_tenant.snapshot.collected_at:
        raise ValueError("The earlier snapshot must be older than the one being reported")

    # Coverage notes go in with the findings: they are not progress, but they
    # tell the comparison what each review could not see, so lost visibility
    # is never reported as a fix. `compare` leaves them out of every group.
    delta = compare(
        before_result.findings,
        after_result.findings,
        previous_snapshot_id=before_tenant.snapshot.snapshot_id,
        current_snapshot_id=after_tenant.snapshot.snapshot_id,
        previous_at=before_tenant.snapshot.collected_at,
        current_at=after_tenant.snapshot.collected_at,
    )

    rows: list[dict[str, Any]] = []
    for key, label in _GROUPS:
        for finding in sorted(getattr(delta, key), key=lambda f: (-f.severity.rank, -f.risk_score)):
            change = delta.changes.get(finding.finding_id)
            detail = ""
            if key == "resolved":
                detail = "No longer found."
            elif key == "new":
                detail = "Not present in the earlier review."
            elif key == "not_revalidated":
                detail = (
                    "Not found this time, but this check, or the accounts it named, could not be fully "
                    "read in this review. It is not shown to be fixed, and is left out of the risk total."
                )
            elif key == "first_assessed":
                detail = (
                    "This check could not be assessed in the earlier review, so this is the first reading, "
                    "not a new problem. It is left out of the risk total."
                )
            elif change is not None:
                parts = []
                if change.previous_count != change.current_count:
                    parts.append(f"Was {change.previous_count} affected, now {change.current_count}.")
                if change.removed:
                    parts.append(f"No longer affected: {_names(change.removed)}.")
                if change.added:
                    parts.append(f"Newly affected: {_names(change.added)}.")
                if change.unconfirmed:
                    parts.append(
                        f"Not rechecked (their data could not be read): {_names(change.unconfirmed)}."
                    )
                detail = " ".join(parts) or "Same as before."
            rows.append({"outcome": label, "key": key, "finding": finding, "detail": detail})

    summary = delta.summary()
    return {
        "platform": for_platform(after_tenant.platform),
        "previous_at": delta.previous_at,
        "current_at": delta.current_at,
        "previous_snapshot_id": delta.previous_snapshot_id,
        "counts": {key: summary[key] for key, _ in _GROUPS},
        "risk": summary["risk"],
        "rows": rows,
        # Open in both reviews: the appendix says so beside this review's date.
        "open_before": [f.finding_id for f in delta.open_in_both],
    }
