"""Retention enforcement.

The data handling policy sets a retention period for each kind of file the
tool writes (section 4). This module is what turns that table into something
that actually happens, and it is intended to be run on a schedule as well as
on demand:

    snapshots           snapshot dir   ICP_RETENTION_DAYS (30)
    API call trails     snapshot dir   ICP_AUDIT_TRAIL_RETENTION_DAYS (365)
    findings and deltas output dir     ICP_FINDINGS_RETENTION_DAYS (30)
    reports             output dir     ICP_REPORT_RETENTION_DAYS (unset: kept,
                                       per the engagement letter)

Only files whose names this tool writes are ever matched; anything else in
either directory is left alone.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from icp.security import crypto

logger = logging.getLogger(__name__)

#: A snapshot ID: YYYYMMDDTHHMMSS[mmm]Z-<hex>. The milliseconds are optional so
#: that files written by earlier builds, which used second precision, are
#: still subject to retention rather than living forever because their names
#: no longer match.
_ID = r"(?P<stamp>\d{8}T\d{6}(?:\d{3})?)Z-[0-9a-f]+"


@dataclass(frozen=True)
class Kind:
    name: str
    folder: str  # "snapshots" or "output": which directory it lives in
    setting: str
    pattern: re.Pattern[str]


KINDS = (
    Kind("snapshots", "snapshots", "ICP_RETENTION_DAYS", re.compile(rf"^.+__{_ID}\.json(?:\.enc)?$")),
    Kind(
        "audit_trails",
        "snapshots",
        "ICP_AUDIT_TRAIL_RETENTION_DAYS",
        re.compile(rf"^{_ID}\.apicalls\.(?:jsonl|manifest\.json)$"),
    ),
    Kind(
        "findings",
        "output",
        "ICP_FINDINGS_RETENTION_DAYS",
        re.compile(rf"__{_ID}__(?:findings|delta)\.json$"),
    ),
    Kind("reports", "output", "ICP_REPORT_RETENTION_DAYS", re.compile(rf"__{_ID}\.(?:html|pdf)$")),
)


@dataclass
class PurgeResult:
    #: Kind -> names deleted (or, in a dry run, that would be).
    deleted: dict[str, list[str]] = field(default_factory=dict)
    #: Names that could not be deleted, with the reason. Not in `deleted`.
    failed: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return sum(len(names) for names in self.deleted.values())


def expired_files(
    root: Path, kind: Kind, retention_days: int, *, now: datetime | None = None
) -> list[Path]:
    """Files of one kind past their retention period.

    Age is taken from the timestamp in the filename, not the filesystem mtime:
    copying a file between machines resets mtime and would silently extend
    retention past what the client was promised.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)
    root = Path(root)
    if not root.is_dir():
        return []
    expired: list[Path] = []
    for path in sorted(root.iterdir()):
        if not path.is_file():
            continue
        match = kind.pattern.search(path.name)
        if match and _parse_stamp(match.group("stamp")) < cutoff:
            expired.append(path)
    return expired


def purge(
    folders: dict[str, Path],
    retention: dict[str, int | None],
    *,
    dry_run: bool = False,
    now: datetime | None = None,
) -> PurgeResult:
    """Delete every file past its kind's retention period.

    `folders` maps "snapshots" and "output" to directories; `retention` maps a
    kind's name to its days, or None to keep that kind. A file whose deletion
    fails is reported in `failed`, never as deleted: the attestation is built
    from this result and must state only what happened.
    """
    result = PurgeResult()
    for kind in KINDS:
        days = retention.get(kind.name)
        if days is None:
            continue
        for path in expired_files(folders[kind.folder], kind, days, now=now):
            if dry_run:
                logger.info("Would delete %s", path.name)
            else:
                try:
                    crypto.secure_delete(str(path))
                except OSError as exc:
                    result.failed[path.name] = f"{type(exc).__name__}: {exc.strerror or exc}"
                    logger.warning("Could not delete %s: %s", path.name, exc)
                    continue
                logger.info("Deleted %s", path.name)
            result.deleted.setdefault(kind.name, []).append(path.name)
    return result


def _parse_stamp(raw: str) -> datetime:
    """Parse a filename timestamp at either second or millisecond precision."""
    fmt = "%Y%m%dT%H%M%S%f" if len(raw) > 15 else "%Y%m%dT%H%M%S"
    return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
