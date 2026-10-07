"""The normalized tenant view every rule reads.

This is the second half of the snapshot boundary. Collectors produce raw
provider JSON; normalizers reduce it to these types. A rule that needs to know
whether it is looking at Google or Microsoft has been written wrongly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from icp.models.enums import Assessability, CheckFamily, Platform, ScopeTier
from icp.models.identity import Identity, OAuthGrant
from icp.models.resource import DomainPolicy, Resource
from icp.models.snapshot import Snapshot


@dataclass(frozen=True)
class AuditStream:
    """One logging stream and whether it is usable for investigation."""

    name: str
    available: bool
    event_count_sampled: int = 0
    probe_window_days: int = 0
    reason: str | None = None


@dataclass(frozen=True)
class TokenLogCoverage:
    """What the token audit log can and cannot tell us about app usage."""

    window_start: datetime
    #: Oldest event actually read. Later than `window_start` when the read was
    #: truncated, and then only that shorter span may be relied on.
    covered_since: datetime
    #: Whether any usage (not consent/revoke) event was seen at all. Without
    #: one, "no recorded use" cannot be told apart from "use not recorded".
    activity_recorded: bool
    truncated: bool
    event_names: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Application:
    """One connected application, across every user who authorized it."""

    client_id: str
    name: str
    is_first_party: bool
    first_party_kind: str | None
    is_anonymous: bool
    users: tuple[str, ...]
    active_users: int
    suspended_users: int
    scopes: tuple[str, ...]
    max_tier: ScopeTier
    last_authorized_at: datetime | None
    last_used_at: datetime | None


@dataclass(frozen=True)
class AppOnlyGrant:
    """A permission an application holds by itself, with no user signed in.

    Microsoft 365 "application permissions": an app holding Mail.Read this way
    can read every mailbox in the organization, at any time. Google has no
    direct equivalent (its closest is domain-wide delegation), so the Google
    normalizer leaves this empty.
    """

    app_id: str
    app_name: str
    permission: str
    tier: ScopeTier
    #: The assessment tool's own app registration. Reported separately, never
    #: as a client finding, and the report says it should be removed afterwards.
    is_assessor: bool = False


@dataclass(frozen=True)
class AppCredential:
    """A secret or certificate an application signs in with (dates only)."""

    app_id: str
    app_name: str
    kind: str  # "secret" or "certificate"
    starts: datetime | None
    expires: datetime | None
    is_assessor: bool = False

    @property
    def lifetime_days(self) -> int | None:
        if self.starts and self.expires:
            return (self.expires - self.starts).days
        return None


@dataclass(frozen=True)
class CoverageGap:
    """A check family that ran on incomplete data.

    Not a failure -- the checks ran and their findings stand -- but a clean
    result in this family is not proof of a clean tenant, and the report says so.
    """

    key: str
    families: tuple[CheckFamily, ...]
    reason: str
    #: (id, label) of what was missed, where it can be named.
    missed: tuple[tuple[str, str], ...] = ()


@dataclass
class NormalizedTenant:
    """Everything a rule is allowed to see."""

    platform: Platform
    tenant_id: str
    snapshot: Snapshot

    identities: list[Identity] = field(default_factory=list)
    grants: list[OAuthGrant] = field(default_factory=list)
    #: The grants above, one entry per application. The report's inventory.
    applications: list[Application] = field(default_factory=list)
    #: None when the token audit log was not collected (or the snapshot predates it).
    token_log: TokenLogCoverage | None = None
    #: From the tenant itself: the name in Account settings > Profile, and the
    #: primary domain. Either may be None if its collector did not run.
    organization_name: str | None = None
    primary_domain: str | None = None
    #: The day Google's sign-in method report describes (YYYY-MM-DD). Google
    #: publishes it one to three days late, so it trails the snapshot.
    mfa_report_date: str | None = None

    @property
    def display_name(self) -> str | None:
        """What the report cover calls this organization, when nothing overrides it."""
        return self.organization_name or self.primary_domain

    resources: list[Resource] = field(default_factory=list)
    audit_streams: list[AuditStream] = field(default_factory=list)
    policy: DomainPolicy | None = None

    #: Check families that could not be assessed, with the reason. Rules consult
    #: this so a permission failure is reported honestly instead of as a pass.
    assessability: dict[CheckFamily, tuple[Assessability, str]] = field(default_factory=dict)

    #: Coverage stats, surfaced in the report's scope statement.
    coverage: dict[str, Any] = field(default_factory=dict)

    #: Families that ran on incomplete data. See `CoverageGap`.
    coverage_gaps: list[CoverageGap] = field(default_factory=list)

    #: Microsoft 365 only (empty for Google): external guests, kept apart from
    #: staff so they never count in staff MFA coverage; app-only permissions;
    #: and application sign-in credentials.
    guests: list[Identity] = field(default_factory=list)
    app_only_grants: list[AppOnlyGrant] = field(default_factory=list)
    app_credentials: list[AppCredential] = field(default_factory=list)

    # -- convenience accessors --------------------------------------------------

    @property
    def users(self) -> list[Identity]:
        return [i for i in self.identities if i.kind.value == "user"]

    @property
    def active_users(self) -> list[Identity]:
        return [u for u in self.users if not u.suspended and not u.archived]

    @property
    def admins(self) -> list[Identity]:
        return [u for u in self.users if u.is_privileged]

    @property
    def super_admins(self) -> list[Identity]:
        return [u for u in self.users if u.is_super_admin]

    def identity_by_id(self, identity_id: str) -> Identity | None:
        return next((i for i in self.identities if i.id == identity_id), None)

    def is_assessable(self, family: CheckFamily) -> bool:
        state = self.assessability.get(family)
        return state is None or state[0] == Assessability.ASSESSED
