"""Best-effort owner-only permissions for client data on disk.

Every file this tool writes about a client -- snapshots, call trails, findings,
deltas, reports, attestations -- goes through `write_private` (or `restrict`
straight after a library writes it), so none is left world-readable by a
umask. On a Docker Desktop bind mount the container cannot change modes; there
the host folder's access list is the control, and run-all.ps1 sets and checks it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

FILE_MODE = 0o600
DIR_MODE = 0o700

#: Folders already warned about, so a bind mount yields one warning, not one per file.
_warned: set[Path] = set()


def restrict(path: Path, mode: int) -> None:
    """Apply `mode` where the filesystem allows it; warn where it cannot.

    Docker Desktop on Windows and macOS presents bind-mounted host folders as
    owned by root. The container runs as an unprivileged user with every
    capability dropped, so `chmod` fails with EPERM even though writing works.
    Aborting there would throw away a completed collection run over a control
    the host filesystem cannot enforce anyway. Encryption at rest, and the host
    folder's access list, are the controls that still hold on such a mount.
    """
    if os.name != "posix":
        _warn_once(
            path,
            "File permissions are not set by this tool on Windows; restrict access to %s on the "
            "host (tools/protect-data-folders.ps1 does this, and run-all.ps1 runs it).",
        )
        return
    try:
        path.chmod(mode)
    except OSError:  # not ours (EPERM), or a read-only mount (EROFS): same answer
        _warn_once(
            path,
            "Could not restrict permissions in %s: it is not owned by this user, typically a "
            "Docker Desktop bind mount from Windows or macOS. Restrict access to this folder "
            "on the host instead (tools/protect-data-folders.ps1 does this, and run-all.ps1 runs it).",
        )


def private_dir(path: Path) -> Path:
    """Create `path` if needed, owner-only."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    restrict(path, DIR_MODE)
    return path


def write_private(path: Path, data: str | bytes) -> Path:
    """Write a file owner-only: created with mode 0600 rather than chmod-ed after."""
    path = Path(path)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), FILE_MODE)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    restrict(path, FILE_MODE)  # an existing file keeps its old mode through O_CREAT
    return path


def _warn_once(path: Path, message: str) -> None:
    folder = path if path.is_dir() else path.parent
    if folder in _warned:
        return
    _warned.add(folder)
    # Set by run-all.ps1 only after tools/protect-data-folders.ps1 has read the
    # host folders' access lists back: then the control is known to be in place.
    if os.environ.get("ICP_HOST_FOLDERS_VERIFIED", "").strip().lower() == "true":
        logger.info("Access to %s is set on the host folder (checked by run-all.ps1).", folder)
        return
    logger.warning(message, folder)
