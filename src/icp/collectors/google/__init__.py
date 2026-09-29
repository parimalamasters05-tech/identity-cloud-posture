"""Google Workspace collection orchestration."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from icp.collectors.base import to_collection_error
from icp.collectors.google.audit import AuditReadinessCollector
from icp.collectors.google.client import GoogleClient
from icp.collectors.google.customer import CustomerProfileCollector
from icp.collectors.google.groups import GroupsCollector
from icp.collectors.google.mfa import MfaCollector
from icp.collectors.google.oauth import OAuthTokensCollector
from icp.collectors.google.policies import WorkspacePoliciesCollector
from icp.collectors.google.roles import RoleAssignmentsCollector, RolesCollector
from icp.collectors.google.sharing import DriveSettingsCollector, PublicDriveItemsCollector
from icp.collectors.google.token_activity import TokenActivityCollector
from icp.collectors.google.users import UsersCollector
from icp.config import Settings
from icp.models.snapshot import CollectionError, Snapshot

logger = logging.getLogger(__name__)

#: Order matters: users must run first because the OAuth collector enumerates
#: tokens per user and needs that list.
COLLECTORS = (
    UsersCollector,
    GroupsCollector,
    RolesCollector,
    RoleAssignmentsCollector,
    MfaCollector,
    OAuthTokensCollector,
    TokenActivityCollector,
    DriveSettingsCollector,
    CustomerProfileCollector,
    WorkspacePoliciesCollector,
    PublicDriveItemsCollector,
    AuditReadinessCollector,
)

#: The brief's week-3 acceptance bar for one full collection run.
COLLECTION_BUDGET_SECONDS = 300


def collect(settings: Settings) -> Snapshot:
    """Run every Google collector and assemble a snapshot.

    Individual collector failures are recorded and the run continues. The only
    thing that aborts a run is a read-only violation, which is a defect.
    """
    settings.require_live_collection()

    started_at = datetime.now(UTC)
    client = GoogleClient(settings)

    # Fail fast on credentials. A per-collector failure is a degraded check; no
    # credential at all is a configuration error, and letting it degrade nine
    # collectors in turn would produce an empty snapshot that looks like a
    # tenant problem rather than a setup problem. This also proves the core
    # scopes were granted, which is what `scopes_used` below asserts.
    client.authenticate()

    artifacts: dict[str, Any] = {}
    errors: list[CollectionError] = []
    partial: dict[str, str] = {}
    refused: set[str] = set()

    for collector_cls in COLLECTORS:
        collector = collector_cls()
        try:
            logger.info("Collecting %s", collector.name)
            truncations_before = len(client.truncations)
            data = collector.collect(client)  # type: ignore[arg-type]
            artifacts[collector.name] = data
            if len(client.truncations) > truncations_before:
                partial[collector.name] = " ".join(client.truncations[truncations_before:])

            if collector.name == "google.users":
                # Hand the user list to the OAuth collector via the client.
                client.known_users = data  # type: ignore[attr-defined]

        except Exception as exc:
            error = to_collection_error(collector.name, exc)
            errors.append(error)
            refused |= set(getattr(exc, "refused_scopes", ()))
            logger.warning("Collector %s degraded: %s", collector.name, error.message)

    # Fails the run loudly if any state-changing request was recorded.
    client.attest_read_only()

    collected_at = datetime.now(UTC)
    elapsed = (collected_at - started_at).total_seconds()
    if elapsed > COLLECTION_BUDGET_SECONDS:
        logger.warning(
            "Collection took %.0fs, over the %ds budget. The OAuth collector (one call per "
            "user) is the usual cause on large tenants.",
            elapsed,
            COLLECTION_BUDGET_SECONDS,
        )

    return Snapshot(
        snapshot_id=_snapshot_id(),
        tenant_id=settings.tenant_id,
        platform="google_workspace",  # type: ignore[arg-type]
        started_at=started_at,
        collected_at=collected_at,
        scopes_used=tuple(sorted({*settings.scopes, *settings.optional_scopes} - refused)),
        scopes_refused=tuple(sorted(refused)),
        artifacts=artifacts,
        errors=tuple(errors),
        partial=partial,
        api_calls=tuple(client.calls),
    )


def load_fixture_snapshot(fixture_dir: Path, tenant_id: str = "dev-fixture") -> Snapshot:
    """Build a snapshot from frozen fixtures.

    This is the offline path the brief calls for: every rule test runs against
    these files, with no tenant access and no credentials. Each fixture file is
    named for the artifact key it provides.

    A set frozen from a live snapshot (`icp freeze-fixtures`) also carries a
    manifest of the run itself. Its degraded collectors are restored as errors:
    dropping them would turn "this could not be read" into "nothing was found".
    """
    from icp.storage.freeze import read_manifest

    artifacts: dict[str, Any] = {}
    for path in sorted(fixture_dir.glob("*.json")):
        if path.name.startswith("_"):
            continue
        artifacts[path.stem.replace("__", ".")] = json.loads(path.read_text("utf-8"))

    if not artifacts:
        raise FileNotFoundError(f"No fixture files found in {fixture_dir}")

    manifest = read_manifest(fixture_dir)
    if manifest is None:
        return Snapshot(
            snapshot_id=_snapshot_id(),
            tenant_id=tenant_id,
            platform="google_workspace",  # type: ignore[arg-type]
            scopes_used=(),
            artifacts=artifacts,
            collected_at=datetime.now(UTC),
        )

    return Snapshot(
        snapshot_id=_snapshot_id(),
        tenant_id=tenant_id,
        platform="google_workspace",  # type: ignore[arg-type]
        started_at=manifest.get("started_at"),
        collected_at=manifest["collected_at"],
        scopes_used=tuple(manifest.get("scopes_used", ())),
        scopes_refused=tuple(manifest.get("scopes_refused", ())),
        artifacts=artifacts,
        errors=tuple(CollectionError(**e) for e in manifest.get("errors", ())),
        partial=manifest.get("partial", {}),
    )


def _snapshot_id() -> str:
    """`20260911T025536123Z-<random>`.

    Millisecond precision matters: `load_latest()` picks a snapshot by sorting
    filenames, so with second precision two collections in the same second would
    be ordered by their random suffix rather than by time -- and "assess the
    latest snapshot" would silently assess the earlier one.
    """
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")[:-3]
    return f"{stamp}Z-{uuid.uuid4().hex[:8]}"


__all__ = ["COLLECTION_BUDGET_SECONDS", "COLLECTORS", "collect", "load_fixture_snapshot"]
