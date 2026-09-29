"""The snapshot -- the architectural boundary this whole project rests on.

Collectors write raw API responses here and nothing downstream ever talks to a
provider API again. That single rule buys offline rule development, free delta
reporting, per-finding evidence traceability, and cheap multi-platform support.

Bump SCHEMA_VERSION on any breaking change to the artifact layout; the loader
refuses to read a snapshot whose major version it does not understand rather
than silently misinterpreting old data.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from icp import __version__
from icp.models.enums import Assessability, Platform

#: 1.1 added `partial`; 1.2 added `started_at` and `scopes_refused`, and made
#: `scopes_used` mean granted rather than requested. All additive; 1.0 loads.
SCHEMA_VERSION = "1.2"


class CollectionError(BaseModel):
    """A partial failure.

    A missing permission degrades exactly one collector; it must never abort the
    run. Every degraded collector is surfaced in the report so the client can see
    what was not examined.
    """

    model_config = ConfigDict(frozen=True)

    collector: str
    assessability: Assessability
    message: str
    http_status: int | None = None
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApiCallRecord(BaseModel):
    """One line of the tool's self-audit trail.

    Recorded for every outbound request so the engagement can produce its own
    evidence of read-only behaviour, to be reconciled against the client's
    tenant-side audit log.
    """

    model_config = ConfigDict(frozen=True)

    method: str
    url: str
    status: int | None = None
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Snapshot(BaseModel):
    """A timestamped, immutable capture of one tenant's configuration."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_VERSION
    snapshot_id: str
    tenant_id: str
    platform: Platform

    #: When collection began. With `collected_at` (when it finished) this is the
    #: window a client filters their own audit log to.
    started_at: datetime | None = None
    #: When collection finished.
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_version: str = __version__

    #: Scopes Google actually granted for this run -- the claim the report makes.
    scopes_used: tuple[str, ...] = ()
    #: Optional scopes requested and refused (not in the delegation entry).
    scopes_refused: tuple[str, ...] = ()
    read_only_attested: bool = True

    artifacts: dict[str, Any] = {}
    errors: tuple[CollectionError, ...] = ()
    #: Collectors that returned data but not all of it (collector -> why).
    #: Distinct from `errors`: the checks run, and the report says they are partial.
    partial: dict[str, str] = {}
    api_calls: tuple[ApiCallRecord, ...] = ()

    def artifact(self, name: str) -> Any:
        """Fetch a collector's payload, or an empty list if it was degraded."""
        return self.artifacts.get(name, [])

    def degraded_collectors(self) -> tuple[str, ...]:
        return tuple(sorted({e.collector for e in self.errors}))

    def content_hash(self) -> str:
        """Integrity hash over the artifacts only.

        Excludes timestamps and the API-call log so that two collections of an
        unchanged tenant hash identically -- useful as a cheap "nothing moved"
        check before running a full delta.
        """
        canonical = json.dumps(self.artifacts, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def major_version(version: str) -> str:
        return version.split(".", 1)[0]
