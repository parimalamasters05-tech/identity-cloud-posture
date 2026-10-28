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
#: Data handling policy, section 4: findings as snapshots; API call trails a
#: year, as evidence of read-only behaviour; reports per the engagement letter.
DEFAULT_FINDINGS_RETENTION_DAYS = 30
DEFAULT_AUDIT_TRAIL_RETENTION_DAYS = 365


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


def _env_optional_int(name: str) -> int | None:
    raw = os.environ.get(name)
    return None if raw is None or not raw.strip() else _env_int(name, 0)


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
    #: This engagement's reviewed exceptions (icp.rules.exceptions). Client data:
    #: kept with the engagement, never in the repository. None: no exceptions.
    exceptions_file: Path | None = None

    # --- behaviour -------------------------------------------------------------
    encrypt_at_rest: bool = True
    #: A deliberately misconfigured test tenant (ICP_TEST_ENVIRONMENT): the only
    #: case in which live collection may write an unencrypted snapshot.
    test_environment: bool = False
    retention_days: int = DEFAULT_RETENTION_DAYS
    findings_retention_days: int = DEFAULT_FINDINGS_RETENTION_DAYS
    audit_trail_retention_days: int = DEFAULT_AUDIT_TRAIL_RETENTION_DAYS
    #: None: reports are kept, per the engagement letter, until set.
    report_retention_days: int | None = None
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
            exceptions_file=Path(os.environ["ICP_EXCEPTIONS_FILE"])
            if os.environ.get("ICP_EXCEPTIONS_FILE")
            else None,
            encrypt_at_rest=_env_bool("ICP_ENCRYPT_AT_REST", True),
            test_environment=_env_bool("ICP_TEST_ENVIRONMENT", False),
            retention_days=_env_int("ICP_RETENTION_DAYS", DEFAULT_RETENTION_DAYS),
            findings_retention_days=_env_int(
                "ICP_FINDINGS_RETENTION_DAYS", DEFAULT_FINDINGS_RETENTION_DAYS
            ),
            audit_trail_retention_days=_env_int(
                "ICP_AUDIT_TRAIL_RETENTION_DAYS", DEFAULT_AUDIT_TRAIL_RETENTION_DAYS
            ),
            report_retention_days=_env_optional_int("ICP_REPORT_RETENTION_DAYS"),
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

    def retention(self) -> dict[str, int | None]:
        """Days each kind of file is kept (see `icp.storage.retention`), checked."""
        periods = {
            "snapshots": (self.retention_days, "ICP_RETENTION_DAYS", 365),
            "audit_trails": (self.audit_trail_retention_days, "ICP_AUDIT_TRAIL_RETENTION_DAYS", 3650),
            "findings": (self.findings_retention_days, "ICP_FINDINGS_RETENTION_DAYS", 365),
            "reports": (self.report_retention_days, "ICP_REPORT_RETENTION_DAYS", 3650),
        }
        for days, name, ceiling in periods.values():
            if days is not None and not 1 <= days <= ceiling:
                raise ConfigError(f"{name} must be between 1 and {ceiling}.")
        return {kind: days for kind, (days, _, _) in periods.items()}

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
