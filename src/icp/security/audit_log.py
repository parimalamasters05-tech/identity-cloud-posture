"""The tool's own audit trail.

Week 1's done-when test is "the tenant's audit log shows read operations only".
That check is performed on the client's side. This is the mirror of it: an
append-only record of every request this process made, hashed and written
alongside the snapshot, so the two logs can be reconciled during delivery.

It is deliberately not a security control -- a compromised process could lie
about its own behaviour. It is evidence, and its value is in the reconciliation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from icp.models.snapshot import ApiCallRecord
from icp.storage._permissions import private_dir, write_private


def summarize(calls: list[ApiCallRecord]) -> dict[str, int]:
    """Count calls by HTTP verb. Goes in the report's methodology appendix."""
    counts: dict[str, int] = {}
    for call in calls:
        counts[call.method.upper()] = counts.get(call.method.upper(), 0) + 1
    return dict(sorted(counts.items()))


def write_audit_trail(path: Path, calls: list[ApiCallRecord], *, tenant_id: str) -> Path:
    """Write the JSONL trail plus a sidecar digest."""
    private_dir(path.parent)
    lines = [
        json.dumps(
            {"method": c.method, "url": c.url, "status": c.status, "at": c.at.isoformat()},
            sort_keys=True,
        )
        for c in calls
    ]
    body = "\n".join(lines) + ("\n" if lines else "")
    write_private(path, body)

    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    manifest = {
        "tenant_id": tenant_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "call_count": len(calls),
        "verb_counts": summarize(calls),
        "sha256": digest,
    }
    write_private(path.with_suffix(".manifest.json"), json.dumps(manifest, indent=2, sort_keys=True))
    return path
