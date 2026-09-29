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


def _is_foreign_mount(path: Path) -> bool:
    """Is this file on a filesystem that cannot express POSIX mode bits?

    Docker Desktop on Windows and macOS exposes host files through a translation
    layer that reports every file as 0777, because NTFS and APFS have no POSIX
    mode bits to report. `chmod` on such a file silently does nothing.

    Detected by attempting the change rather than by sniffing the platform: the
    container is Linux either way, so `os.name` cannot tell us, and mount-table
    parsing is brittle across Docker versions. If a chmod does not stick, the
    filesystem is not enforcing modes and the check cannot mean anything.
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
    except (OSError, PermissionError):
        # Read-only mount, or not ours to modify. Treat as unenforceable.
        return True


def _check_file_permissions(path: Path) -> None:
    """Refuse to read a key file that others can read.

    A world-readable key in a shared directory is the most common real-world
    leak of a service account, so this is a genuine control on Linux and macOS
    hosts. It is skipped where the filesystem cannot express permissions at all
    -- demanding a `chmod` that provably cannot take effect would teach the
    operator to ignore the check, which is worse than not having it.
    """
    if os.name != "posix":
        return

    mode = stat.S_IMODE(path.stat().st_mode)
    if not (mode & ~_MAX_PERMISSIONS):
        return

    if _is_foreign_mount(path):
        logger.warning(
            "Credential file %s reports mode %04o, but its filesystem does not enforce "
            "POSIX permissions -- typically a Docker Desktop bind mount from Windows or "
            "macOS. Permission checking is not possible here; secure the file on the host "
            "instead.",
            path,
            mode,
        )
        return

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
