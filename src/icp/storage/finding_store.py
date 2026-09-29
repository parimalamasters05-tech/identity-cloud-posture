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
from icp.storage._permissions import restrict

#: 1.1 added summary.partial_coverage (additive).
#: 2.0 finding IDs no longer hash the affected accounts (`id_scheme`). Not
#:     additive: a 1.x file's IDs cannot be matched against a 2.x file's.
FINDINGS_SCHEMA_VERSION = "2.0"
_FILE_MODE = 0o600


class IncompatibleFindings(Exception):
    """A findings file whose IDs were built by a different ID scheme."""


class FindingStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

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

        path.write_text(json.dumps(document, indent=2, sort_keys=False), encoding="utf-8")
        restrict(path, _FILE_MODE)
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


def deletion_attestation(tenant_id: str, deleted: list[str], *, operator: str = "") -> dict[str, Any]:
    """The document handed to a client when their data is destroyed.

    Promised by the data handling policy; generating it from the actual delete
    operation rather than writing it by hand is what makes it true.
    """
    return {
        "attestation": "client data deletion",
        "tenant_id": tenant_id,
        "deleted_at": datetime.now(UTC).isoformat(),
        "file_count": len(deleted),
        "files": sorted(deleted),
        "operator": operator or os.environ.get("ICP_OPERATOR", "unspecified"),
        "method": "cryptographic key material and file contents overwritten, then unlinked",
    }
