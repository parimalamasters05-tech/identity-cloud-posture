"""Encryption at rest and log redaction.

Both exist because a snapshot is a complete map of who can access what in a
client's organization -- valuable to exactly the people the assessment is meant
to protect against.
"""

from __future__ import annotations

import base64
import logging
import os
import stat
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from icp.security import crypto
from icp.security.credentials import CredentialError, _check_file_permissions
from icp.security.redaction import RedactingFilter, mask_email, redact

pytestmark = pytest.mark.security


# -- crypto --------------------------------------------------------------------


@pytest.fixture
def key() -> str:
    return crypto.generate_key()


def test_round_trip(key):
    blob = crypto.encrypt(b"sensitive tenant configuration", key_b64=key)
    assert crypto.decrypt(blob, key_b64=key) == b"sensitive tenant configuration"


def test_ciphertext_does_not_contain_the_plaintext(key):
    blob = crypto.encrypt(b"departed.finance@client.example", key_b64=key)
    assert b"departed.finance" not in blob


def test_generated_keys_are_unique_and_correctly_sized():
    keys = {crypto.generate_key() for _ in range(20)}
    assert len(keys) == 20
    assert all(len(base64.b64decode(k)) == 32 for k in keys)


def test_wrong_key_fails_rather_than_returning_garbage(key):
    blob = crypto.encrypt(b"secret", key_b64=key)
    with pytest.raises(InvalidTag):
        crypto.decrypt(blob, key_b64=crypto.generate_key())


def test_tampered_ciphertext_is_rejected(key):
    """AES-GCM authentication: a modified snapshot must not decrypt."""
    blob = bytearray(crypto.encrypt(b"secret payload", key_b64=key))
    blob[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        crypto.decrypt(bytes(blob), key_b64=key)


def test_wrong_aad_is_rejected(key):
    """The snapshot ID is bound to the ciphertext, so files cannot be swapped."""
    blob = crypto.encrypt(b"payload", key_b64=key, aad=b"snapshot-B"[:0] + b"snapshot-A")
    with pytest.raises(InvalidTag):
        crypto.decrypt(blob, key_b64=key, aad=b"snapshot-B")


def test_missing_key_fails_closed(monkeypatch):
    """Never degrade to plaintext because a key is absent."""
    monkeypatch.delenv("ICP_SNAPSHOT_KEY", raising=False)
    with pytest.raises(crypto.CryptoUnavailable, match="ICP_SNAPSHOT_KEY"):
        crypto.encrypt(b"x")


def test_malformed_key_is_rejected(monkeypatch):
    monkeypatch.setenv("ICP_SNAPSHOT_KEY", "not-base64!!")
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.encrypt(b"x")


def test_short_key_is_rejected(monkeypatch):
    monkeypatch.setenv("ICP_SNAPSHOT_KEY", base64.b64encode(b"tooshort").decode())
    with pytest.raises(crypto.CryptoUnavailable, match="32 bytes"):
        crypto.encrypt(b"x")


def test_is_encrypted_discriminates(key):
    assert crypto.is_encrypted(crypto.encrypt(b"x", key_b64=key))
    assert not crypto.is_encrypted(b'{"schema_version": "1.0"}')


def test_secure_delete_removes_the_file(tmp_path: Path):
    target = tmp_path / "snapshot.json"
    target.write_bytes(b"A" * 4096)
    crypto.secure_delete(str(target))
    assert not target.exists()


def test_secure_delete_is_safe_on_a_missing_file(tmp_path: Path):
    crypto.secure_delete(str(tmp_path / "never-existed.json"))


# -- credential hygiene --------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_world_readable_key_file_is_rejected(tmp_path: Path):
    """The most common real-world key leak is a 644 file in a shared directory."""
    key_file = tmp_path / "sa.json"
    key_file.write_text("{}")
    key_file.chmod(0o644)
    with pytest.raises(CredentialError, match="0644"):
        _check_file_permissions(key_file)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_owner_only_key_file_is_accepted(tmp_path: Path):
    key_file = tmp_path / "sa.json"
    key_file.write_text("{}")
    key_file.chmod(0o600)
    _check_file_permissions(key_file)
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


# -- redaction -----------------------------------------------------------------


def test_email_is_masked_but_domain_survives():
    """Domains are operationally useful; local parts are personal."""
    assert mask_email("alice.smith@client.example") == "a***h@client.example"


def test_two_different_users_stay_distinguishable():
    a = mask_email("alice@client.example")
    b = mask_email("bob@client.example")
    assert a != b


def test_short_local_parts_are_handled():
    assert mask_email("jo@client.example").endswith("@client.example")


def test_private_key_block_is_removed():
    text = "key: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----"
    assert "MIIEvQIBADAN" not in redact(text)
    assert "REDACTED PRIVATE KEY" in redact(text)


def test_bearer_token_is_removed():
    assert "ya29.a0AfH6" not in redact("Authorization: Bearer ya29.a0AfH6SomeLongToken")


def test_long_secret_is_removed():
    secret = "AIzaSyC" + "x7Kd93Lm" * 6
    assert secret not in redact(f"apiKey={secret}")


def test_logging_filter_masks_emails_in_messages(caplog):
    logger = logging.getLogger("icp.test.redaction")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO):
        logger.info("Collected grants for %s", "departed.finance@client.example")
    combined = caplog.text
    assert "departed.finance" not in combined
    assert "client.example" in combined


def test_redaction_is_idempotent():
    once = redact("contact alice.smith@client.example")
    assert redact(once) == once


def test_numeric_log_arguments_keep_their_type(caplog):
    """Redaction must not break `%d` formatting.

    Coercing arguments to strings turns an ordinary log line into a traceback on
    the operator's screen in the middle of a collection run -- which is exactly
    when a tool needs to look calm.
    """
    logger = logging.getLogger("icp.test.redaction.numeric")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO):
        logger.info("Wrote snapshot %s (%d artifacts, encrypted=%s)", "snap-1", 9, False)
    assert "9 artifacts" in caplog.text


def test_dict_style_log_arguments_are_redacted(caplog):
    logger = logging.getLogger("icp.test.redaction.dict")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO):
        logger.info("user=%(email)s count=%(n)d", {"email": "sam.okafor@client.example", "n": 3})
    assert "sam.okafor" not in caplog.text
    assert "count=3" in caplog.text
