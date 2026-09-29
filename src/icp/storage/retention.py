"""Retention enforcement.

The data handling policy promises a 30-day retention window and a deletion
attestation. This module is what turns that from a sentence in a PDF into
something that actually happens, and it is intended to be run on a schedule as
well as on demand.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from icp.security import crypto

logger = logging.getLogger(__name__)

#: Snapshot filenames embed a UTC timestamp:
#:   tenant__YYYYMMDDTHHMMSSmmmZ-<hex>.json[.enc]
#: The milliseconds are optional so that snapshots written by earlier builds,
#: which used second precision, are still subject to retention rather than
#: living forever because their names no longer match.
_STAMP = re.compile(r"__(\d{8}T\d{6}(?:\d{3})?)Z-")


def expired_files(root: Path, retention_days: int, *, now: datetime | None = None) -> list[Path]:
    """Find files past the retention window.

    Age is taken from the timestamp in the filename, not the filesystem mtime:
    copying a snapshot between machines resets mtime and would silently extend
    retention past what the client was promised.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)
    expired: list[Path] = []

    for path in sorted(Path(root).glob("*")):
        if not path.is_file():
            continue
        match = _STAMP.search(path.name)
        if not match:
            continue
        stamped = _parse_stamp(match.group(1))
        if stamped < cutoff:
            expired.append(path)

    return expired


def purge(
    root: Path, retention_days: int, *, dry_run: bool = False, now: datetime | None = None
) -> list[str]:
    """Delete expired files. Returns the names deleted, for the attestation."""
    deleted: list[str] = []
    for path in expired_files(root, retention_days, now=now):
        if dry_run:
            logger.info("Would delete %s", path.name)
        else:
            crypto.secure_delete(str(path))
            logger.info("Deleted %s", path.name)
        deleted.append(path.name)
    return deleted


def _parse_stamp(raw: str) -> datetime:
    """Parse a filename timestamp at either second or millisecond precision."""
    fmt = "%Y%m%dT%H%M%S%f" if len(raw) > 15 else "%Y%m%dT%H%M%S"
    return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
