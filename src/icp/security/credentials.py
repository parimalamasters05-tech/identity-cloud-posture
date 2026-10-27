"""Credential loading and hygiene checks.

Two things go wrong with service-account keys in practice: they get committed,
and they get left world-readable in a shared directory. Both are checked here,
loudly, before the key is used.

Preferred order:
  1. Workload Identity Federation / ADC   - no long-lived key material at all
  2. Key file referenced by env var       - permission-checked on every load
  3. Key JSON in an env var               - for CI; never written to disk
"""

from __future__ import annotations

import json
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from icp.security.scopes import assert_read_only

logger = logging.getLogger(__name__)

#: Anything looser than owner-read/write on a key file is rejected.
_MAX_PERMISSIONS = 0o600


class CredentialError(RuntimeError):
    """Raised for a missing, malformed, or insecurely stored credential."""


@dataclass(frozen=True)
class GoogleCredentialSource:
    """Where the Google credential came from. Recorded in the run manifest."""

    kind: str  # "adc" | "key_file" | "key_env"
    detail: str  # path or a non-sensitive description -- never key material


#: Filesystems through which Docker Desktop shares host files with a container.
#: None can express POSIX modes (every file reports as 0777 or 0644), so access
#: is controlled by the host's own permissions. Seen live: WSL2 shares a
#: Windows drive as 9p with aname=drvfs.
_HOST_SHARE_TYPES = frozenset({"fakeowner", "fuse.grpcfuse", "grpcfuse", "osxfs", "fuse.osxfs", "drvfs"})

_MOUNTINFO = Path("/proc/self/mountinfo")


def _mount_type(path: Path, mountinfo: Path = _MOUNTINFO) -> tuple[str, str] | None:
    """(filesystem type, its options) of the mount holding `path`, if known."""
    try:
        lines = mountinfo.read_text("utf-8").splitlines()
    except OSError:
        return None
    target = str(path.resolve())
    best: tuple[int, str, str] | None = None
    for line in lines:
        head, sep, tail = line.partition(" - ")
        fields = head.split()
        if not sep or len(fields) < 5:
            continue
        # Spaces and similar arrive octal-escaped (\040).
        point = fields[4].encode().decode("unicode_escape")
        if target != point and not target.startswith(point.rstrip("/") + "/"):
            continue
        parts = tail.split()
        if parts and (best is None or len(point) > best[0]):
            best = (len(point), parts[0], parts[2] if len(parts) > 2 else "")
    return (best[1], best[2]) if best else None


def _is_host_share(path: Path, mountinfo: Path = _MOUNTINFO) -> bool:
    """Is this file shared from the host by Docker Desktop (no POSIX modes)?

    Identified by the mount's filesystem type, never by a failed chmod: a key
    mounted read-only from an ordinary Linux disk also refuses chmod, and its
    loose mode is real. Treating that failure as "cannot check" let such a key
    through.
    """
    found = _mount_type(path, mountinfo)
    if found is None:
        return False
    fstype, options = found
    return fstype in _HOST_SHARE_TYPES or (fstype == "9p" and "aname=drvfs" in options)


def _chmod_is_ignored(path: Path) -> bool | None:
    """Does a chmod on this file silently not take effect? None: it was refused.

    For a translation layer not in `_HOST_SHARE_TYPES`. A refusal (read-only,
    not ours) proves nothing about enforcement, so the caller fails closed.
    """
    try:
        original = stat.S_IMODE(path.stat().st_mode)
        path.chmod(0o600)
        applied = stat.S_IMODE(path.stat().st_mode)
        if applied != 0o600:
            return True
        # It stuck: a real POSIX filesystem. Put it back if we changed it.
        if original != 0o600:
            path.chmod(original)
        return False
    except OSError:
        return None


def _check_file_permissions(path: Path, *, mountinfo: Path = _MOUNTINFO) -> None:
    """Refuse to read a key file that others can read, or whose access cannot be checked.

    A world-readable key in a shared directory is the most common real-world
    leak of a service account. Only a file shared from the host by Docker
    Desktop, whose filesystem has no modes, is let through with a warning:
    there the host's access list is the control, and run-all.ps1 checks it.
    Anything else that cannot be verified is refused.
    """
    if os.name != "posix":
        logger.warning(
            "Credential file %s: permissions are not checked on Windows by this tool. "
            "run-all.ps1 checks the key file's access list on the host.",
            path,
        )
        return

    mode = stat.S_IMODE(path.stat().st_mode)
    if not (mode & ~_MAX_PERMISSIONS):
        return

    if _is_host_share(path, mountinfo):
        logger.warning(
            "Credential file %s reports mode %04o, but it is shared from the host by Docker "
            "Desktop, which has no POSIX permissions. Its access is controlled on the host: "
            "run-all.ps1 checks that only you, SYSTEM and Administrators can read it.",
            path,
            mode,
        )
        return

    ignored = _chmod_is_ignored(path)
    if ignored:
        logger.warning(
            "Credential file %s reports mode %04o on a filesystem that ignores chmod. "
            "Permission checking is not possible here; secure the file on the host.",
            path,
            mode,
        )
        return
    if ignored is None:
        raise CredentialError(
            f"Credential file {path} has permissions {mode:04o} and they cannot be checked or "
            "tightened here (read-only or not ours). Tighten it where it is stored "
            f"(`chmod 600`) before running against any tenant."
        )
    raise CredentialError(
        f"Credential file {path} has permissions {mode:04o}. "
        f"Tighten it to 0600 (`chmod 600 {path}`) before running against any tenant."
    )


def _validate_key_material(info: dict[str, Any]) -> None:
    required = {"type", "client_email", "private_key"}
    missing = required - info.keys()
    if missing:
        raise CredentialError(f"Service account key is missing required field(s): {sorted(missing)}")
    if info.get("type") != "service_account":
        raise CredentialError(f"Expected a service_account key, got type={info.get('type')!r}")


def load_google_credentials(
    *,
    subject: str,
    scopes: tuple[str, ...],
    key_file: str | None = None,
    key_json_env: str = "ICP_GOOGLE_SA_KEY_JSON",
) -> tuple[Any, GoogleCredentialSource]:
    """Build delegated, read-only Google credentials.

    `subject` is the super-admin the service account impersonates via
    domain-wide delegation. Scopes are validated against the read-only allowlist
    *before* any credential is constructed, so an over-broad scope set can never
    reach Google's token endpoint.
    """
    assert_read_only(list(scopes))

    try:
        from google.oauth2 import service_account
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CredentialError("google-auth is required for live collection.") from exc

    raw_json = os.environ.get(key_json_env)
    if raw_json:
        try:
            info = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise CredentialError(f"{key_json_env} does not contain valid JSON.") from exc
        _validate_key_material(info)
        creds = service_account.Credentials.from_service_account_info(info, scopes=list(scopes))
        source = GoogleCredentialSource("key_env", f"env:{key_json_env}")
    elif key_file:
        path = Path(key_file).expanduser()
        if not path.is_file():
            raise CredentialError(f"Credential file not found: {path}")
        _check_file_permissions(path)
        info = json.loads(path.read_text("utf-8"))
        _validate_key_material(info)
        creds = service_account.Credentials.from_service_account_file(str(path), scopes=list(scopes))
        source = GoogleCredentialSource("key_file", str(path))
    else:
        raise CredentialError(
            f"No Google credential configured. Set ICP_GOOGLE_KEY_FILE or {key_json_env}. See .env.example."
        )

    delegated = creds.with_subject(subject)
    logger.info("Loaded Google credentials via %s, impersonating %s", source.kind, subject)
    return delegated, source
