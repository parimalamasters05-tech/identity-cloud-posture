"""OAuth scope -> blast-radius classification.

The project brief calls the taxonomy "the actual intellectual property of the
project", so it lives in `config/scope_severity_taxonomy.yaml` as data, not in
code. It can be reviewed by someone who does not read Python, diffed between
versions, and extended with Microsoft Graph scopes in week 5 without touching
this loader.

Matching is longest-prefix: an exact match wins, then the most specific prefix,
then the pattern rules, then UNKNOWN. UNKNOWN is deliberately weighted in the
middle of the range -- an unclassified scope is a research task, not a pass.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from icp.models.enums import ScopeTier

logger = logging.getLogger(__name__)

DEFAULT_TAXONOMY_PATH = Path("config/scope_severity_taxonomy.yaml")


@dataclass
class ScopeTaxonomy:
    exact: dict[str, dict[str, Any]] = field(default_factory=dict)
    prefixes: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    version: str = "unknown"

    #: Google's own OAuth clients, by client ID -> display name. Matched on ID
    #: only; a display name is chosen by whoever registered the app.
    first_party_clients: dict[str, str] = field(default_factory=dict)
    #: client ID -> "developer_tool" | "device_sign_in".
    first_party_kinds: dict[str, str] = field(default_factory=dict)
    #: Scopes only Google's own browsers and devices can obtain.
    google_session_scopes: frozenset[str] = frozenset()

    #: Scopes seen at runtime that matched nothing. Surfaced in the report so the
    #: taxonomy improves with every engagement rather than silently rotting.
    unclassified: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: Path) -> ScopeTaxonomy:
        data = yaml.safe_load(path.read_text("utf-8")) or {}
        exact: dict[str, dict[str, Any]] = {}
        prefixes: list[tuple[str, dict[str, Any]]] = []

        for entry in data.get("scopes", []) or []:
            record = {
                "tier": ScopeTier(entry.get("tier", "unknown")),
                "description": entry.get("description", ""),
                "label": entry.get("label", ""),
            }
            if entry.get("match") == "prefix":
                prefixes.append((entry["scope"], record))
            else:
                exact[entry["scope"]] = record

        # Longest prefix first so the most specific rule wins.
        prefixes.sort(key=lambda item: len(item[0]), reverse=True)

        return cls(
            exact=exact,
            prefixes=prefixes,
            version=str(data.get("version", "unknown")),
            first_party_clients={
                str(entry["client_id"]): str(entry.get("name", entry["client_id"]))
                for entry in data.get("first_party_clients", []) or []
            },
            first_party_kinds={
                str(entry["client_id"]): str(entry.get("kind", "developer_tool"))
                for entry in data.get("first_party_clients", []) or []
            },
            google_session_scopes=frozenset(data.get("google_session_scopes", []) or []),
        )

    @classmethod
    def load_default(cls, config_dir: Path | None = None) -> ScopeTaxonomy:
        path = (config_dir / "scope_severity_taxonomy.yaml") if config_dir else DEFAULT_TAXONOMY_PATH
        if not path.exists():
            # Search upward: keeps `pytest` and `icp` working from any directory.
            for parent in [Path.cwd(), *Path(__file__).resolve().parents]:
                candidate = parent / DEFAULT_TAXONOMY_PATH
                if candidate.exists():
                    path = candidate
                    break
        return cls.load(path)

    def _lookup(self, scope: str) -> dict[str, Any] | None:
        if scope in self.exact:
            return self.exact[scope]
        for prefix, record in self.prefixes:
            if scope.startswith(prefix):
                return record
        return None

    def tier_for(self, scope: str) -> ScopeTier:
        record = self._lookup(scope)
        if record is None:
            self.unclassified.add(scope)
            logger.debug("Unclassified OAuth scope: %s", scope)
            return ScopeTier.UNKNOWN
        return record["tier"]

    def description_for(self, scope: str) -> str:
        record = self._lookup(scope)
        return record["description"] if record else "Unclassified scope: manual review required."

    def is_first_party(self, client_id: str) -> bool:
        return client_id in self.first_party_clients

    def first_party_kind(self, client_id: str, scopes: tuple[str, ...] | list[str] = ()) -> str | None:
        """ "developer_tool", "device_sign_in", or None for a third party.

        By client ID first. Failing that, a grant holding only Google-session
        scopes is a browser or device sign-in: those scopes are not issued to
        outside apps, so unlike a display name they cannot be claimed.
        """
        if client_id in self.first_party_kinds:
            return self.first_party_kinds[client_id]
        if scopes and self.google_session_scopes and set(scopes) <= self.google_session_scopes:
            return "device_sign_in"
        return None

    def is_classified(self, scope: str) -> bool:
        return self._lookup(scope) is not None

    def label_for(self, scope: str) -> str:
        record = self._lookup(scope)
        return record["label"] if record and record["label"] else scope
