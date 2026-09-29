"""Remediation content library loader.

Content lives in `config/remediation.yaml` so it can be edited by whoever writes
best -- which is not necessarily whoever writes Python. Missing content is a
loud failure, not a blank section: shipping a report with an empty remediation
box is worse than not shipping it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PATH = Path("config/remediation.yaml")


class MissingRemediationContent(KeyError):
    """Raised when a rule references a remediation key with no content."""


@dataclass(frozen=True)
class Remediation:
    key: str
    title: str
    impact: str
    steps: tuple[str, ...]
    verification: str = ""
    owner_hint: str = ""
    references: tuple[str, ...] = ()


@dataclass
class RemediationLibrary:
    entries: dict[str, Remediation]
    version: str = "unknown"

    @classmethod
    def load(cls, path: Path) -> RemediationLibrary:
        data = yaml.safe_load(path.read_text("utf-8")) or {}
        entries = {}
        for key, raw in (data.get("remediations") or {}).items():
            entries[key] = Remediation(
                key=key,
                title=str(raw.get("title", key)),
                impact=str(raw.get("impact", "")).strip(),
                steps=tuple(str(s) for s in raw.get("steps", [])),
                verification=str(raw.get("verification", "")),
                owner_hint=str(raw.get("owner_hint", "")),
                references=tuple(str(r) for r in raw.get("references", [])),
            )
        return cls(entries=entries, version=str(data.get("version", "unknown")))

    @classmethod
    def load_default(cls, config_dir: Path | None = None) -> RemediationLibrary:
        path = (config_dir / "remediation.yaml") if config_dir else DEFAULT_PATH
        if not path.exists():
            for parent in [Path.cwd(), *Path(__file__).resolve().parents]:
                candidate = parent / DEFAULT_PATH
                if candidate.exists():
                    path = candidate
                    break
        return cls.load(path)

    def get(self, key: str) -> Remediation:
        if key not in self.entries:
            raise MissingRemediationContent(
                f"No remediation content for {key!r}. Every rule must have content in "
                "config/remediation.yaml before it can appear in a client report."
            )
        return self.entries[key]

    def missing_for(self, keys: set[str]) -> set[str]:
        return {k for k in keys if k not in self.entries}


def load_framework(path: Path | None = None) -> dict[str, Any]:
    """Load the NIST CSF 2.0 subcategory descriptions."""
    target = path or Path("config/framework_mapping.yaml")
    if not target.exists():
        for parent in [Path.cwd(), *Path(__file__).resolve().parents]:
            candidate = parent / "config/framework_mapping.yaml"
            if candidate.exists():
                target = candidate
                break
    data = yaml.safe_load(target.read_text("utf-8")) or {}
    return data
