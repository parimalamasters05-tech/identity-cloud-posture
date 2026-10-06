"""Provider data -> normalized tenant view."""

from __future__ import annotations

from typing import TYPE_CHECKING

from icp.normalizers.base import AuditStream, NormalizedTenant

if TYPE_CHECKING:
    from icp.models.snapshot import Snapshot

__all__ = ["AuditStream", "NormalizedTenant", "normalize_snapshot"]


def normalize_snapshot(snapshot: Snapshot) -> NormalizedTenant:
    """Pick the normalizer for the snapshot's platform."""
    from icp.models.enums import Platform

    if snapshot.platform == Platform.GOOGLE_WORKSPACE:
        from icp.normalizers.google import normalize

        return normalize(snapshot)
    if snapshot.platform == Platform.MICROSOFT_365:
        from icp.normalizers.microsoft import normalize as normalize_m365

        return normalize_m365(snapshot)
    raise ValueError(f"No normalizer for platform {snapshot.platform}")
