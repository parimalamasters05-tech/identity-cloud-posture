"""Encryption at rest for snapshots and findings.

A snapshot is a complete inventory of a client's identity configuration: who is
an admin, who has no MFA, which accounts are dormant. It is a target. The data
handling policy promises encryption at rest and a 30-day retention window, and
this module is what makes that promise true rather than aspirational.

AES-256-GCM, key supplied via ICP_SNAPSHOT_KEY (base64, 32 bytes). The key is
never written to disk by this tool and never appears in a snapshot.
"""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

_MAGIC = b"ICP1"
_NONCE_BYTES = 12
_KEY_BYTES = 32


class CryptoUnavailable(RuntimeError):
    """Raised when encryption is requested but cannot be performed.

    Fails closed on purpose: a missing dependency or key must never degrade
    silently into writing client identity data in plaintext.
    """


def generate_key() -> str:
    """Mint a new base64 key for ICP_SNAPSHOT_KEY."""
    return base64.b64encode(secrets.token_bytes(_KEY_BYTES)).decode("ascii")


def _load_key(key_b64: str | None) -> bytes:
    raw = key_b64 or os.environ.get("ICP_SNAPSHOT_KEY", "")
    if not raw:
        raise CryptoUnavailable(
            "ICP_SNAPSHOT_KEY is not set. Generate one with `icp keygen` and store it in "
            "your secret manager, or pass --no-encrypt for dev-tenant runs only."
        )
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise CryptoUnavailable("ICP_SNAPSHOT_KEY is not valid base64.") from exc
    if len(key) != _KEY_BYTES:
        raise CryptoUnavailable(f"ICP_SNAPSHOT_KEY must decode to {_KEY_BYTES} bytes, got {len(key)}.")
    return key


def _aesgcm(key: bytes):  # type: ignore[no-untyped-def]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CryptoUnavailable(
            "The `cryptography` package is required for encryption at rest. "
            "Install it, or pass --no-encrypt for dev-tenant runs only."
        ) from exc
    return AESGCM(key)


def encrypt(plaintext: bytes, *, key_b64: str | None = None, aad: bytes = b"") -> bytes:
    """Encrypt. Output layout: MAGIC || nonce || ciphertext+tag."""
    key = _load_key(key_b64)
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ciphertext = _aesgcm(key).encrypt(nonce, plaintext, aad)
    return _MAGIC + nonce + ciphertext


def decrypt(blob: bytes, *, key_b64: str | None = None, aad: bytes = b"") -> bytes:
    """Decrypt, verifying the authentication tag."""
    if not blob.startswith(_MAGIC):
        raise CryptoUnavailable("Not an ICP encrypted file (bad magic header).")
    key = _load_key(key_b64)
    nonce = blob[len(_MAGIC) : len(_MAGIC) + _NONCE_BYTES]
    ciphertext = blob[len(_MAGIC) + _NONCE_BYTES :]
    return _aesgcm(key).decrypt(nonce, ciphertext, aad)


def is_encrypted(blob: bytes) -> bool:
    return blob.startswith(_MAGIC)


def secure_delete(path: str | Path) -> None:
    """Best-effort overwrite before unlink.

    Note honestly: on copy-on-write and flash-backed filesystems this does not
    guarantee the original blocks are unrecoverable. It raises the bar; the real
    control is short retention plus full-disk encryption, both of which the data
    handling policy requires.
    """
    target = Path(path)
    if not target.exists():
        return
    length = target.stat().st_size
    with target.open("r+b", buffering=0) as handle:
        handle.write(secrets.token_bytes(length))
        handle.flush()
        os.fsync(handle.fileno())
    target.unlink()
