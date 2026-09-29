"""Pre-flight checks for a live tenant.

The first live run is where this project is most likely to fail, and the failure
mode is unhelpful: one collector returns 403 and you cannot tell whether the
service account is wrong, a scope was missed in the delegation grant, or the
licence tier simply does not expose that surface.

This makes one minimal read per API surface and reports each independently, so a
partial delegation grant produces "you did not grant
admin.reports.audit.readonly" rather than a stack trace forty seconds into a
collection run. Seconds to run; worth doing before every engagement.

Every probe is a GET, issued through the same read-only transport guard as
collection, and the run is attested afterwards like any other.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from icp.collectors.google.mfa import PARAMETERS as MFA_PARAMETERS
from icp.config import ConfigError, Settings

logger = logging.getLogger(__name__)

BASE = "https://www.googleapis.com/auth/"


@dataclass
class Probe:
    """One API surface, and what is lost if it is unreachable."""

    name: str
    scope: str
    families: str
    required: bool
    call: Callable[[Any, Settings], Any] | None = field(default=None, repr=False)


@dataclass
class ProbeResult:
    probe: Probe
    ok: bool
    detail: str = ""
    http_status: int | None = None

    @property
    def status(self) -> str:
        if self.ok:
            return "OK"
        return "FAIL" if self.probe.required else "DEGRADED"


# -- probes --------------------------------------------------------------------


def _users(client: Any, settings: Settings) -> Any:
    service = client.service("admin", "directory_v1")
    return client.call(service.users(), "list", customer=settings.customer_id, maxResults=1)


def _groups(client: Any, settings: Settings) -> Any:
    service = client.service("admin", "directory_v1")
    return client.call(service.groups(), "list", customer=settings.customer_id, maxResults=1)


def _roles(client: Any, settings: Settings) -> Any:
    service = client.service("admin", "directory_v1")
    return client.call(service.roles(), "list", customer=settings.customer_id, maxResults=1)


def _domains(client: Any, settings: Settings) -> Any:
    service = client.service("admin", "directory_v1")
    return client.call(service.domains(), "list", customer=settings.customer_id)


def _tokens(client: Any, settings: Settings) -> Any:
    """The scope behind the differentiator, probed against the impersonated admin."""
    service = client.service("admin", "directory_v1")
    return client.call(service.tokens(), "list", userKey=settings.admin_subject)


def _reports(client: Any, settings: Settings) -> Any:  # noqa: ARG001 - uniform probe signature
    service = client.service("admin", "reports_v1")
    return client.call(service.activities(), "list", userKey="all", applicationName="login", maxResults=1)


def _usage(client: Any, settings: Settings) -> Any:  # noqa: ARG001 - uniform probe signature
    """Usage reports are a different surface, and a different scope, from activities."""
    from datetime import UTC, datetime, timedelta

    service = client.service("admin", "reports_v1")
    date = (datetime.now(UTC) - timedelta(days=3)).strftime("%Y-%m-%d")
    return client.call(
        service.userUsageReport(),
        "get",
        userKey="all",
        date=date,
        # The exact fields the collector asks for: probing a different, valid
        # field let a misnamed one pass preflight and fail every collection.
        parameters=",".join(MFA_PARAMETERS),
        maxResults=1,
    )


def _drive(client: Any, settings: Settings) -> Any:  # noqa: ARG001 - uniform probe signature
    service = client.service("drive", "v3")
    return client.call(service.files(), "list", pageSize=1, fields="files(id)")


def _policies(client: Any, settings: Settings) -> Any:  # noqa: ARG001 - uniform probe signature
    """Needs the Cloud Identity API enabled on the GCP project, not only the scope."""
    service = client.service(
        "cloudidentity", "v1", optional_scopes=(f"{BASE}cloud-identity.policies.readonly",)
    )
    return client.call(service.policies(), "list", pageSize=1)


def _customer(client: Any, settings: Settings) -> Any:
    service = client.service(
        "admin", "directory_v1", optional_scopes=(f"{BASE}admin.directory.customer.readonly",)
    )
    return client.call(service.customers(), "get", customerKey=settings.customer_id)


PROBES: tuple[Probe, ...] = (
    Probe(
        "Directory: users",
        f"{BASE}admin.directory.user.readonly",
        "MFA coverage, stale accounts, admin sprawl",
        required=True,
        call=_users,
    ),
    Probe(
        "Directory: admin roles",
        f"{BASE}admin.directory.rolemanagement.readonly",
        "admin role sprawl",
        required=True,
        call=_roles,
    ),
    Probe(
        "Directory: OAuth tokens",
        f"{BASE}admin.directory.user.security",
        "third-party app grants (the differentiator)",
        required=True,
        call=_tokens,
    ),
    Probe(
        "Directory: groups",
        f"{BASE}admin.directory.group.readonly",
        "group inventory",
        required=False,
        call=_groups,
    ),
    Probe(
        "Directory: domains",
        f"{BASE}admin.directory.domain.readonly",
        "primary domain name",
        required=False,
        call=_domains,
    ),
    Probe(
        "Reports: audit activities",
        f"{BASE}admin.reports.audit.readonly",
        "logging readiness, second-factor method strength",
        required=False,
        call=_reports,
    ),
    Probe(
        "Reports: usage (2SV strength)",
        f"{BASE}admin.reports.usage.readonly",
        "second-factor method strength",
        required=False,
        call=_usage,
    ),
    Probe(
        "Drive: file metadata",
        f"{BASE}drive.metadata.readonly",
        "publicly shared files",
        required=False,
        call=_drive,
    ),
    Probe(
        "Cloud Identity: Workspace settings",
        f"{BASE}cloud-identity.policies.readonly",
        "Drive external-sharing warnings",
        required=False,
        call=_policies,
    ),
    Probe(
        "Directory: organization profile",
        f"{BASE}admin.directory.customer.readonly",
        "the organization name on the report cover (otherwise the primary domain)",
        required=False,
        call=_customer,
    ),
)


# -- offline checks ------------------------------------------------------------


def check_configuration(settings: Settings) -> list[ProbeResult]:
    """Everything checkable without contacting Google."""
    from pathlib import Path

    from icp.security.credentials import _check_file_permissions
    from icp.security.scopes import ScopeViolation, assert_read_only

    results: list[ProbeResult] = []

    def record(name: str, ok: bool, detail: str, required: bool = True) -> None:
        results.append(ProbeResult(Probe(name, "", "", required), ok, detail))

    try:
        settings.require_live_collection()
        record("Environment variables", True, f"tenant={settings.tenant_id}")
    except ConfigError as exc:
        record("Environment variables", False, str(exc))

    try:
        assert_read_only([*settings.scopes, *settings.optional_scopes])
        record(
            "Scope allowlist",
            True,
            f"{len(settings.scopes)} core + {len(settings.optional_scopes)} optional scopes, all read-only",
        )
    except ScopeViolation as exc:
        record("Scope allowlist", False, str(exc))

    if settings.google_key_file:
        path = Path(settings.google_key_file).expanduser()
        if not path.is_file():
            record("Credential file", False, f"not found: {path}")
        else:
            try:
                _check_file_permissions(path)
                record("Credential file", True, f"{path} (0600)")
            except Exception as exc:
                record("Credential file", False, str(exc))
    else:
        record(
            "Credential file",
            True,
            "no key file set; expecting ICP_GOOGLE_SA_KEY_JSON or ADC",
            required=False,
        )

    return results


# -- live checks ---------------------------------------------------------------


def _token_error(settings: Settings, scopes: tuple[str, ...]) -> str | None:
    """Ask Google for a token for exactly these scopes. No API call is made."""
    import google_auth_httplib2
    import httplib2

    from icp.security.credentials import load_google_credentials

    credentials, _ = load_google_credentials(
        subject=settings.admin_subject, scopes=scopes, key_file=settings.google_key_file
    )
    try:
        credentials.refresh(
            google_auth_httplib2.Request(httplib2.Http(timeout=settings.request_timeout_seconds))
        )
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def check_delegation(
    settings: Settings,
    token_error: Callable[[Settings, tuple[str, ...]], str | None] = _token_error,
) -> list[ProbeResult] | None:
    """Name the exact scopes missing from the domain-wide delegation entry.

    Google issues one token for the whole scope set, and refuses it outright
    (`unauthorized_client`) if even one scope is not delegated. Every probe then
    fails with the same opaque error. Asking for one scope at a time turns that
    into "this scope is missing". Returns None when the full set is granted.
    """
    error = token_error(settings, tuple(settings.scopes))
    if error is None:
        return None

    if "unauthorized_client" not in error:
        return [ProbeResult(Probe("Delegation: token", "", "every check", True), False, error)]

    results: list[ProbeResult] = []
    for scope in settings.scopes:
        missing = token_error(settings, (scope,)) is not None
        results.append(
            ProbeResult(
                Probe(
                    f"Delegation: {scope.removeprefix(BASE)}",
                    scope,
                    "every check -- Google refuses the whole sign-in if any scope is missing",
                    required=True,
                ),
                not missing,
                (f"missing from the domain-wide delegation entry. Add exactly:\n           {scope}")
                if missing
                else "delegated",
            )
        )

    if all(not r.ok for r in results):
        results.append(
            ProbeResult(
                Probe("Delegation: client ID", "", "every check", True),
                False,
                "no scope at all is delegated. Check that the client ID in Admin console > "
                "Security > API controls > Domain-wide delegation is this service account's, "
                "and that the entry was saved. A new or edited entry can take a few minutes, "
                "occasionally longer, to apply.",
            )
        )
    return results


def check_api_access(settings: Settings) -> list[ProbeResult]:
    """One minimal read per API surface, each reported independently."""
    from icp.collectors.google.client import GoogleClient

    delegation = check_delegation(settings)
    if delegation is not None:
        return delegation

    client = GoogleClient(settings)
    results: list[ProbeResult] = []

    for probe in PROBES:
        assert probe.call is not None
        try:
            probe.call(client, settings)
            results.append(ProbeResult(probe, True, "reachable"))
        except Exception as exc:
            status = getattr(getattr(exc, "resp", None), "status", None)
            results.append(ProbeResult(probe, False, explain(exc, probe, status), status))

    # Nothing above may have issued a write. Attested before any client data is
    # collected, so a control failure surfaces at the cheapest possible moment.
    client.attest_read_only()
    return results


def explain(exc: Exception, probe: Probe, status: int | None) -> str:
    """Turn a provider error into the next thing to do."""
    if "unauthorized_client" in str(exc):
        return (
            "this scope is not in the domain-wide delegation entry, so Google refused the "
            "token. Add exactly:\n"
            f"           {probe.scope}"
        )
    if status in (401, 403):
        # Google returns 403 for two unrelated problems, and telling the
        # operator to fix the wrong one costs them an hour. `accessNotConfigured`
        # means the API itself is not enabled on the GCP project; anything else
        # is a delegation gap.
        if "accessNotConfigured" in str(exc) or "has not been used in project" in str(exc):
            return (
                f"the API is not enabled on your GCP project ({status} "
                "accessNotConfigured). Enable it in the Cloud Console under "
                "APIs & Services > Library, then wait a few minutes. This is not "
                "a scope problem."
            )
        return (
            f"access denied ({status}). Add this scope to the domain-wide delegation "
            f"grant for the service account's client ID:\n           {probe.scope}"
        )
    if status == 404:
        return (
            f"not available ({status}). Usually a licence tier that does not expose this "
            "surface. The affected checks will report as coverage notes, not as passes."
        )
    if status == 400:
        return (
            f"bad request ({status}). Check ICP_GOOGLE_CUSTOMER_ID and that "
            "ICP_GOOGLE_ADMIN_SUBJECT is a real super-admin in this tenant."
        )
    return f"{type(exc).__name__}: {exc}"
