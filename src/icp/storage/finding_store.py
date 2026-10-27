"""Findings persistence.

The JSON findings file is a client deliverable in its own right -- it is what a
client's own tooling ingests, and what the delta report reads on the next run.
Its shape is therefore a contract, and `schema_version` is part of it.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from icp.models.finding import ID_NAMESPACE, Finding
from icp.risk import scoring
from icp.risk.severity import RiskMatrix
from icp.rules.engine import AssessmentResult
from icp.storage._permissions import private_dir, write_private

#: 1.1 added summary.partial_coverage (additive).
#: 2.0 finding IDs no longer hash the affected accounts (`id_scheme`). Not
#:     additive: a 1.x file's IDs cannot be matched against a 2.x file's.
FINDINGS_SCHEMA_VERSION = "2.0"


class IncompatibleFindings(Exception):
    """A findings file whose IDs were built by a different ID scheme."""


class FindingStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        private_dir(self.root)

    def path_for(self, tenant_id: str, snapshot_id: str) -> Path:
        return self.root / f"{tenant_id}__{snapshot_id}__findings.json"

    def save(
        self,
        result: AssessmentResult,
        *,
        tenant_id: str,
        snapshot_id: str,
        matrix: RiskMatrix | None = None,
    ) -> Path:
        matrix = matrix or RiskMatrix.load_default()
        path = self.path_for(tenant_id, snapshot_id)

        document: dict[str, Any] = {
            "schema_version": FINDINGS_SCHEMA_VERSION,
            "id_scheme": ID_NAMESPACE,
            "tenant_id": tenant_id,
            "snapshot_id": snapshot_id,
            "generated_at": result.generated_at.isoformat(),
            "risk_matrix_version": matrix.version,
            "summary": {
                "total": len(result.findings),
                "by_severity": result.counts_by_severity(),
                "rules_run": result.rules_run,
                "rules_failed": [{"rule_id": r, "error": e} for r, e in result.rules_failed],
                "unassessable": result.unassessable,
                "partial_coverage": result.partial_coverage,
            },
            "findings": [
                {
                    **json.loads(f.model_dump_json()),
                    "score_breakdown": scoring.explain(f, matrix),
                }
                for f in result.findings
            ],
        }

        write_private(path, json.dumps(document, indent=2, sort_keys=False))
        return path

    def load(self, path: Path) -> list[Finding]:
        """Load findings for comparison.

        Refuses a file from another ID scheme. Comparing across schemes would
        report every finding as resolved and re-opened -- a plausible-looking
        delta that is entirely wrong. The snapshot is kept, so the fix is cheap.
        """
        data = json.loads(Path(path).read_text("utf-8"))
        scheme = data.get("id_scheme", "icp.finding.v1")
        if scheme != ID_NAMESPACE:
            raise IncompatibleFindings(
                f"{Path(path).name} uses finding-ID scheme {scheme}; this version uses "
                f"{ID_NAMESPACE}. Regenerate it with `icp assess --snapshot <its snapshot>` "
                "before comparing."
            )
        return [Finding.model_validate(f) for f in data.get("findings", [])]

    def load_latest(self, tenant_id: str) -> list[Finding]:
        candidates = sorted(self.root.glob(f"{tenant_id}__*__findings.json"))
        return self.load(candidates[-1]) if candidates else []


#: What `purge` does to a file, and nothing more. It never touches the
#: encryption key: that lives in a secret manager, outside this tool's reach.
DELETION_METHOD = (
    "Each file's contents overwritten once with random data, then the file unlinked. "
    "On copy-on-write and flash-backed storage overwriting does not guarantee the old "
    "blocks are unrecoverable; the data handling policy (section 5) explains the other "
    "controls. Encryption keys are not handled by this tool."
)


def deletion_attestation(
    tenant_id: str,
    deleted: dict[str, list[str]],
    *,
    retention: dict[str, int | None],
    failed: dict[str, str] | None = None,
    operator: str = "",
) -> dict[str, Any]:
    """The document handed to a client when their data is destroyed.

    Promised by the data handling policy; generating it from the actual delete
    operation rather than writing it by hand is what makes it true. So it lists
    only files actually deleted, and names any that could not be.
    """
    names = sorted(name for group in deleted.values() for name in group)
    return {
        "attestation": "client data deletion",
        "tenant_id": tenant_id,
        "deleted_at": datetime.now(UTC).isoformat(),
        "file_count": len(names),
        "files": names,
        "by_kind": {kind: sorted(group) for kind, group in sorted(deleted.items())},
        "retention_days": {kind: days if days is not None else "kept" for kind, days in retention.items()},
        "not_deleted": [{"file": name, "reason": why} for name, why in sorted((failed or {}).items())],
        "operator": operator or os.environ.get("ICP_OPERATOR", "unspecified"),
        "method": DELETION_METHOD,
    }
