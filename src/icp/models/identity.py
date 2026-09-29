"""Normalized identity model.

Every collector's output is reduced to these types before any rule sees it.
Rules must never import a provider SDK or reference a provider-specific field
name -- that is what keeps `rules/` platform-agnostic when M365 lands.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from icp.models.enums import IdentityKind, Platform, ScopeTier


class MfaMethod(BaseModel):
    """A single enrolled second factor."""

    model_config = ConfigDict(frozen=True)

    method: str = Field(description="e.g. security_key, totp, sms, backup_code")
    is_phishing_resistant: bool = False


class Identity(BaseModel):
    """A user, service account, group, or application principal."""

    model_config = ConfigDict(frozen=True)

    id: str
    platform: Platform
    kind: IdentityKind
    primary_email: str | None = None
    display_name: str | None = None

    suspended: bool = False
    archived: bool = False

    is_admin: bool = False
    admin_roles: tuple[str, ...] = ()
    is_super_admin: bool = False
    is_delegated_admin: bool = False

    mfa_enrolled: bool = False
    mfa_enforced: bool = False
    mfa_methods: tuple[MfaMethod, ...] = ()
    #: False when the provider's method report did not include this account.
    #: "Not in the report" is not "no security key": such an account is left
    #: out of the method-strength check and named in a coverage note instead.
    mfa_method_known: bool = True

    created_at: datetime | None = None
    last_login_at: datetime | None = None

    org_unit: str | None = None

    @property
    def is_privileged(self) -> bool:
        return self.is_super_admin or self.is_admin or self.is_delegated_admin

    @property
    def has_phishing_resistant_mfa(self) -> bool:
        return any(m.is_phishing_resistant for m in self.mfa_methods)

    @property
    def label(self) -> str:
        return self.primary_email or self.display_name or self.id


class OAuthScope(BaseModel):
    """One scope string plus its classified blast radius."""

    model_config = ConfigDict(frozen=True)

    scope: str
    tier: ScopeTier = ScopeTier.UNKNOWN
    description: str | None = None

    @property
    def weight(self) -> int:
        return self.tier.weight


class OAuthGrant(BaseModel):
    """A third-party application authorization held by one identity.

    This is the core object behind check family 7, the project's differentiator.
    One grant == one (user, application) pair. Aggregation across users happens
    in `rules/oauth_grant_risk.py`, never here.
    """

    model_config = ConfigDict(frozen=True)

    platform: Platform
    client_id: str
    app_name: str | None = None

    user_id: str
    user_email: str | None = None

    scopes: tuple[OAuthScope, ...] = ()
    is_native_app: bool = False
    is_anonymous_app: bool = Field(
        default=False,
        description="Google flags apps it cannot identify; a strong shadow-IT signal.",
    )
    #: From the token audit log. None means "not in the log's window", which is
    #: not the same as "never": the log keeps about six months.
    last_authorized_at: datetime | None = None
    last_used_at: datetime | None = None
    is_first_party: bool = Field(
        default=False,
        description="Google's own tool, matched by client ID. Not third-party vendor risk.",
    )
    #: For first-party grants: "developer_tool" (gcloud) or "device_sign_in"
    #: (Chrome, Android). Only developer tools are reported, by GWS-SVC-003.
    first_party_kind: str | None = None

    @property
    def max_tier(self) -> ScopeTier:
        if not self.scopes:
            return ScopeTier.UNKNOWN
        return max((s.tier for s in self.scopes), key=lambda t: t.weight)

    @property
    def scope_strings(self) -> tuple[str, ...]:
        return tuple(s.scope for s in self.scopes)
