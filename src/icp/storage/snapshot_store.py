"""Snapshot persistence.

Snapshots hold a complete map of a client's identity configuration, so they are
written encrypted by default, with restrictive file permissions, and with a
schema-version guard on read. Plaintext is possible but must be asked for
explicitly, and the file says so in its own name.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from icp.models.snapshot import SCHEMA_VERSION, Snapshot
from icp.security import crypto
from icp.storage._permissions import restrict

logger = logging.getLogger(__name__)

_FILE_MODE = 0o600
_DIR_MODE = 0o700

#: Snapshot filenames only: `tenant__YYYYMMDDTHHMMSSmmmZ-<hex>.json[.enc]`.
#:
#: Matching on the full shape rather than the `.json` extension matters because
#: operators reasonably point ICP_SNAPSHOT_DIR and ICP_OUTPUT_DIR at the same
#: folder. Without this, `icp report` picks up a findings file, fails schema
#: validation, and shows a pydantic traceback instead of a report.
_SNAPSHOT_NAME = re.compile(r"^.+__\d{8}T\d{6}(?:\d{3})?Z-[0-9a-f]{8}\.json(?:\.enc)?$")


class SnapshotStoreError(RuntimeError):
    pass


class SnapshotStore:
    def __init__(self, root: Path, *, encrypt: bool = True, key_b64: str | None = None) -> None:
        self.root = Path(root)
        self.encrypt = encrypt
        self.key_b64 = key_b64
        self.root.mkdir(parents=True, exist_ok=True)
        restrict(self.root, _DIR_MODE)

    # -- paths ------------------------------------------------------------------

    def path_for(self, snapshot: Snapshot) -> Path:
        suffix = "json.enc" if self.encrypt else "json"
        tenant = _safe_component(snapshot.tenant_id)
        return self.root / f"{tenant}__{snapshot.snapshot_id}.{suffix}"

    def list_snapshots(self, tenant_id: str | None = None) -> list[Path]:
        """Snapshots for a tenant, oldest first.

        Filenames carry a millisecond timestamp, so lexicographic order is
        collection order and `list_snapshots()[-1]` is genuinely the latest.
        """
        pattern = f"{_safe_component(tenant_id)}__*" if tenant_id else "*"
        return sorted(
            (p for p in self.root.glob(pattern) if _SNAPSHOT_NAME.match(p.name)),
            key=lambda p: p.name,
        )

    # -- write ------------------------------------------------------------------

    def save(self, snapshot: Snapshot) -> Path:
        payload = snapshot.model_dump_json(indent=None).encode("utf-8")
        path = self.path_for(snapshot)

        if self.encrypt:
            # The snapshot ID is bound into the ciphertext as additional
            # authenticated data, so a file cannot be silently swapped for
            # another tenant's snapshot without failing decryption.
            payload = crypto.encrypt(payload, key_b64=self.key_b64, aad=snapshot.snapshot_id.encode())

        path.write_bytes(payload)
        restrict(path, _FILE_MODE)

        logger.info(
            "Wrote snapshot %s (%d artifacts, encrypted=%s)",
            snapshot.snapshot_id,
            len(snapshot.artifacts),
            self.encrypt,
        )
        return path

    # -- read -------------------------------------------------------------------

    def load(self, path: Path) -> Snapshot:
        blob = Path(path).read_bytes()

        if crypto.is_encrypted(blob):
            snapshot_id = _snapshot_id_from_name(Path(path).name)
            blob = crypto.decrypt(blob, key_b64=self.key_b64, aad=snapshot_id.encode())

        data = json.loads(blob.decode("utf-8"))
        _assert_compatible(data.get("schema_version", "0"))
        return Snapshot.model_validate(data)

    def load_latest(self, tenant_id: str) -> Snapshot | None:
        candidates = self.list_snapshots(tenant_id)
        return self.load(candidates[-1]) if candidates else None


def _assert_compatible(version: str) -> None:
    """Refuse a snapshot from a future or incompatible schema.

    Reading it anyway would mean silently misinterpreting client data, which is
    strictly worse than failing.
    """
    if Snapshot.major_version(version) != Snapshot.major_version(SCHEMA_VERSION):
        raise SnapshotStoreError(
            f"Snapshot schema {version} is incompatible with this build ({SCHEMA_VERSION})."
        )


def _snapshot_id_from_name(name: str) -> str:
    stem = name.split("__", 1)[-1]
    for suffix in (".json.enc", ".json"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def _safe_component(value: str | None) -> str:
    """Keep tenant identifiers from escaping the snapshot directory."""
    cleaned = "".join(c if c.isalnum() or c in "-_." else "-" for c in (value or "unknown"))
    return cleaned.strip(".-") or "unknown"
