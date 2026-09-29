"""Runtime configuration.

Everything comes from the environment. Nothing sensitive is ever read from a
file inside the repository, and `Settings` has no field that could hold a
secret's value -- only the *location* of one. That keeps key material out of
tracebacks, `repr()` output, and crash reports.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from icp.security.scopes import optional_scopes, sorted_scopes

DEFAULT_RETENTION_DAYS = 30


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


class ConfigError(RuntimeError):
    """Raised for missing or invalid configuration."""


@dataclass(frozen=True)
class Settings:
    """Resolved settings for one run."""

    # --- tenant identification -------------------------------------------------
    tenant_id: str = ""
    customer_id: str = "my_customer"
    admin_subject: str = ""
    primary_domain: str = ""

    # --- credential *locations* (never values) ---------------------------------
    google_key_file: str | None = None

    # --- paths -----------------------------------------------------------------
    snapshot_dir: Path = Path("snapshots")
    output_dir: Path = Path("output")
    fixture_dir: Path = Path("fixtures")
    config_dir: Path = Path("config")

    # --- behaviour -------------------------------------------------------------
    encrypt_at_rest: bool = True
    retention_days: int = DEFAULT_RETENTION_DAYS
    max_page_size: int = 200
    request_timeout_seconds: int = 60
    max_retries: int = 5
    offline: bool = False

    scopes: tuple[str, ...] = field(default_factory=sorted_scopes)
    optional_scopes: tuple[str, ...] = field(default_factory=optional_scopes)

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            tenant_id=os.environ.get("ICP_TENANT_ID", "").strip(),
            customer_id=os.environ.get("ICP_GOOGLE_CUSTOMER_ID", "my_customer").strip(),
            admin_subject=os.environ.get("ICP_GOOGLE_ADMIN_SUBJECT", "").strip(),
            primary_domain=os.environ.get("ICP_GOOGLE_PRIMARY_DOMAIN", "").strip(),
            google_key_file=os.environ.get("ICP_GOOGLE_KEY_FILE") or None,
            snapshot_dir=Path(os.environ.get("ICP_SNAPSHOT_DIR", "snapshots")),
            output_dir=Path(os.environ.get("ICP_OUTPUT_DIR", "output")),
            fixture_dir=Path(os.environ.get("ICP_FIXTURE_DIR", "fixtures")),
            config_dir=Path(os.environ.get("ICP_CONFIG_DIR", "config")),
            encrypt_at_rest=_env_bool("ICP_ENCRYPT_AT_REST", True),
            retention_days=_env_int("ICP_RETENTION_DAYS", DEFAULT_RETENTION_DAYS),
            max_page_size=_env_int("ICP_MAX_PAGE_SIZE", 200),
            request_timeout_seconds=_env_int("ICP_REQUEST_TIMEOUT", 60),
            max_retries=_env_int("ICP_MAX_RETRIES", 5),
            offline=_env_bool("ICP_OFFLINE", False),
        )

    def require_live_collection(self) -> None:
        """Validate the fields a real tenant run needs. Fails before authenticating."""
        missing = [
            name
            for name, value in (
                ("ICP_TENANT_ID", self.tenant_id),
                ("ICP_GOOGLE_ADMIN_SUBJECT", self.admin_subject),
                ("ICP_GOOGLE_PRIMARY_DOMAIN", self.primary_domain),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                "Missing required environment variable(s) for live collection: "
                + ", ".join(missing)
                + ". Copy .env.example to .env and fill it in."
            )
        if "@" not in self.admin_subject:
            raise ConfigError("ICP_GOOGLE_ADMIN_SUBJECT must be a super-admin email address.")
        if self.retention_days < 1 or self.retention_days > 365:
            raise ConfigError("ICP_RETENTION_DAYS must be between 1 and 365.")

    def safe_summary(self) -> dict[str, str | int | bool]:
        """Non-sensitive settings echoed into the run manifest and report appendix."""
        return {
            "tenant_id": self.tenant_id,
            "primary_domain": self.primary_domain,
            "encrypt_at_rest": self.encrypt_at_rest,
            "retention_days": self.retention_days,
            "scope_count": len(self.scopes),
            "offline": self.offline,
        }
