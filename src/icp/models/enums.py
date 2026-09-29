"""Shared enumerations for the normalized data model.

These values are part of the report's public contract: they appear in the
machine-readable JSON findings file that clients receive. Changing a value is a
breaking change and requires a schema version bump in `models/snapshot.py`.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """String-valued enum that serializes as a plain string."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class Platform(StrEnum):
    GOOGLE_WORKSPACE = "google_workspace"
    MICROSOFT_365 = "microsoft_365"
    AWS = "aws"


class CheckFamily(StrEnum):
    """The seven v1 check families. Order matches the project brief."""

    MFA_COVERAGE = "mfa_coverage"
    ADMIN_ROLE_SPRAWL = "admin_role_sprawl"
    STALE_ACCOUNTS = "stale_accounts"
    SERVICE_ACCOUNT_PRIVILEGE = "service_account_privilege"
    EXTERNAL_SHARING = "external_sharing"
    LOGGING_READINESS = "logging_readiness"
    OAUTH_GRANTS = "oauth_grants"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class Confidence(StrEnum):
    """How certain the rule is that the finding is real.

    CONFIRMED  - read directly from an authoritative API field
    HIGH       - derived from authoritative fields with a documented assumption
    MEDIUM     - inferred from activity data that may be incomplete
    LOW        - heuristic; must be labelled as such in the report
    """

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IdentityKind(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    GROUP = "group"
    APPLICATION = "application"


class ResourceKind(StrEnum):
    DRIVE_SETTING = "drive_setting"
    SHARED_DRIVE = "shared_drive"
    DOMAIN_SETTING = "domain_setting"
    AUDIT_SETTING = "audit_setting"
    STORAGE_BUCKET = "storage_bucket"


class ScopeTier(StrEnum):
    """Blast-radius tiers for an OAuth scope. Defined in config/scope_severity_taxonomy.yaml."""

    ADMIN_EQUIVALENT = "admin_equivalent"
    FULL_DATA_READ = "full_data_read"
    FULL_DATA_WRITE = "full_data_write"
    SCOPED_DATA = "scoped_data"
    METADATA_ONLY = "metadata_only"
    SIGN_IN_ONLY = "sign_in_only"
    UNKNOWN = "unknown"

    @property
    def weight(self) -> int:
        return _SCOPE_TIER_WEIGHT[self]


_SCOPE_TIER_WEIGHT = {
    ScopeTier.ADMIN_EQUIVALENT: 10,
    ScopeTier.FULL_DATA_WRITE: 9,
    ScopeTier.FULL_DATA_READ: 8,
    ScopeTier.SCOPED_DATA: 4,
    ScopeTier.METADATA_ONLY: 2,
    ScopeTier.SIGN_IN_ONLY: 1,
    ScopeTier.UNKNOWN: 5,
}


class FindingStatus(StrEnum):
    """Only meaningful in a delta report."""

    NEW = "new"
    PERSISTING = "persisting"
    #: Still open, but fewer accounts or lower severity than last time.
    IMPROVED = "improved"
    RESOLVED = "resolved"
    REGRESSED = "regressed"


class Assessability(StrEnum):
    """Whether a check could run at all against this tenant.

    NOT_ASSESSABLE is reported explicitly rather than silently omitted -- a check
    that could not run must never look like a check that passed.
    """

    ASSESSED = "assessed"
    NOT_ASSESSABLE_LICENSE = "not_assessable_license"
    NOT_ASSESSABLE_PERMISSION = "not_assessable_permission"
    NOT_ASSESSABLE_ERROR = "not_assessable_error"
