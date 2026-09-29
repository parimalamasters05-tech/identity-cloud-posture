"""Normalized non-identity configuration objects.

Deliberately narrow: this project collects *configuration and metadata only*.
There is no model here that can hold message bodies, file contents, or any
document payload, and that absence is enforced by
`tests/security/test_data_minimization.py`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from icp.models.enums import Platform, ResourceKind


class Resource(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    platform: Platform
    kind: ResourceKind
    name: str
    settings: dict[str, Any] = {}

    externally_shared: bool = False
    publicly_accessible: bool = False
    owner_id: str | None = None


class DomainPolicy(BaseModel):
    """Tenant-wide settings that several rules read."""

    model_config = ConfigDict(frozen=True)

    platform: Platform
    domain: str
    mfa_enforced_org_wide: bool = False
    # None means "not collected". A concrete default here once made a rule
    # report "sharing allowed, no warning" on every tenant, observed or not.
    external_sharing_allowed: bool | None = None
    external_sharing_warning_enabled: bool | None = None
    link_sharing_default: str | None = None
    audit_log_retention_days: int | None = None
    admin_alerting_enabled: bool = False
    less_secure_apps_allowed: bool = False
    raw: dict[str, Any] = {}
