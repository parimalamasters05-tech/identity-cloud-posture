"""Best-effort owner-only permissions for client data on disk."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def restrict(path: Path, mode: int) -> None:
    """Apply `mode` where the filesystem allows it; warn where it cannot.

    Docker Desktop on Windows and macOS presents bind-mounted host folders as
    owned by root. The container runs as an unprivileged user with every
    capability dropped, so `chmod` fails with EPERM even though writing works.
    Aborting there would throw away a completed collection run over a control
    the host filesystem cannot enforce anyway. Encryption at rest is the
    control that still holds on such a mount.
    """
    if os.name != "posix":
        return
    try:
        path.chmod(mode)
    except PermissionError:
        logger.warning(
            "Could not set mode %04o on %s: it is not owned by this user, typically a "
            "Docker Desktop bind mount from Windows or macOS. Restrict access to this "
            "folder on the host instead.",
            mode,
            path,
        )
