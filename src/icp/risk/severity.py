"""Base severity from an explicit impact x exposure matrix.

Transparent and arithmetic, never a black box. Clients challenge rankings, and
being able to show the arithmetic is what wins that conversation -- so the
matrix is data in `config/risk_matrix.yaml` and it is printed verbatim in the
report's methodology appendix.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from icp.models.enums import Severity

DEFAULT_MATRIX_PATH = Path("config/risk_matrix.yaml")


@dataclass(frozen=True)
class RiskMatrix:
    """impact (1-5) x exposure (1-5) -> base severity and base score."""

    matrix: dict[tuple[int, int], str]
    modifiers: dict[str, float]
    #: remediation key -> (base hours, hours per affected item, cap). A flat
    #: estimate is (hours, 0, hours).
    effort_defaults: dict[str, tuple[float, float, float]]
    version: str = "unknown"

    @classmethod
    def load(cls, path: Path) -> RiskMatrix:
        data = yaml.safe_load(path.read_text("utf-8")) or {}
        matrix: dict[tuple[int, int], str] = {}
        for row in data.get("matrix", []) or []:
            matrix[(int(row["impact"]), int(row["exposure"]))] = str(row["severity"])
        return cls(
            matrix=matrix,
            modifiers={str(k): float(v) for k, v in (data.get("modifiers") or {}).items()},
            effort_defaults={str(k): _effort_entry(v) for k, v in (data.get("effort_hours") or {}).items()},
            version=str(data.get("version", "unknown")),
        )

    @classmethod
    def load_default(cls, config_dir: Path | None = None) -> RiskMatrix:
        path = (config_dir / "risk_matrix.yaml") if config_dir else DEFAULT_MATRIX_PATH
        if not path.exists():
            for parent in [Path.cwd(), *Path(__file__).resolve().parents]:
                candidate = parent / DEFAULT_MATRIX_PATH
                if candidate.exists():
                    path = candidate
                    break
        return cls.load(path)

    def severity(self, impact: int, exposure: int) -> Severity:
        impact = max(1, min(5, impact))
        exposure = max(1, min(5, exposure))
        return Severity(self.matrix.get((impact, exposure), "medium"))

    def modifier(self, name: str, default: float = 1.0) -> float:
        return self.modifiers.get(name, default)

    def effort(self, remediation_key: str, default: float = 1.0, *, items: int = 1) -> float:
        """Estimated hours to fix, scaled by how many items the fix touches.

        Flat estimates misrank: "restrict public links" cost 3 hours for 3
        files or for 300, which buried a critical 20-minute fix under mediums.
        """
        base, per_item, cap = self.effort_defaults.get(remediation_key, (default, 0.0, default))
        return round(min(base + per_item * max(items, 1), max(cap, base)), 2)

    def effort_table(self) -> list[dict[str, Any]]:
        """Renderable form for the rubric."""
        return [
            {"key": k, "base": b, "per_item": p, "cap": c}
            for k, (b, p, c) in sorted(self.effort_defaults.items())
        ]

    def as_table(self) -> list[dict[str, Any]]:
        """Renderable form for the methodology appendix."""
        return [
            {"impact": i, "exposure": e, "severity": self.matrix.get((i, e), "medium")}
            for i in range(5, 0, -1)
            for e in range(1, 6)
        ]


def _effort_entry(value: Any) -> tuple[float, float, float]:
    """`1.5` (flat) or `{base: 0.25, per_item: 0.1, cap: 8}`."""
    if isinstance(value, dict):
        base = float(value.get("base", 0.0))
        return base, float(value.get("per_item", 0.0)), float(value.get("cap", base))
    return float(value), 0.0, float(value)
