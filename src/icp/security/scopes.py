"""The read-only scope allowlist -- control #1 of three.

The tool's core promise to a client is that it cannot change anything in their
tenant. That promise is enforced in three independent places, so that no single
mistake can break it:

  1. this module  - only these scopes may ever be requested (runtime, pre-auth)
  2. readonly.py  - unsafe HTTP verbs are blocked in the transport (runtime)
  3. tools/verify_readonly.py - no write-capable call exists in the source (CI)

Adding a scope here is a deliberate act that should be reviewed like a change to
a security boundary, because it is one.
"""

from __future__ import annotations

BASE = "https://www.googleapis.com/auth/"

#: Every scope the Google Workspace collector is permitted to request.
GOOGLE_READONLY_SCOPES: frozenset[str] = frozenset(
    {
        f"{BASE}admin.directory.user.readonly",
        # Required to enumerate third-party OAuth tokens (check family 7).
        # Google exposes no ".readonly" variant of this scope; the transport
        # guard in readonly.py is what constrains it to reads.
        f"{BASE}admin.directory.user.security",
        f"{BASE}admin.directory.rolemanagement.readonly",
        f"{BASE}admin.directory.group.readonly",
        f"{BASE}admin.directory.domain.readonly",
        f"{BASE}admin.directory.orgunit.readonly",
        f"{BASE}admin.reports.audit.readonly",
        # Activity logs and usage reports are separate surfaces with separate
        # scopes. `audit.readonly` covers activities().list; the 2SV
        # method-strength data comes from userUsageReport and needs this one.
        # Discovered the hard way: the activity probe passed and the MFA
        # collector still returned 403 insufficientPermissions.
        f"{BASE}admin.reports.usage.readonly",
        # File names, owners and sharing settings only -- no file content.
        # Replaced drive.readonly, which can read every file's contents; the
        # public-files check never needed them. Compared side by side on the dev
        # tenant before switching: identical results. drive.readonly is now
        # deliberately NOT on this list, so the tool cannot even request it.
        f"{BASE}drive.metadata.readonly",
        # Workspace settings -- Drive sharing policy, 2SV enforcement -- via the
        # Cloud Identity Policy API. Needs the "Cloud Identity API" enabled on
        # the GCP project as well as this scope in the delegation grant.
        f"{BASE}cloud-identity.policies.readonly",
        # The organization's own name, from Account > Account settings > Profile,
        # for the report cover. Without it the cover falls back to the primary
        # domain -- a name typed into config is exactly what this replaces.
        f"{BASE}admin.directory.customer.readonly",
    }
)

#: Substrings that must never appear in a requested scope.
_WRITE_MARKERS = (
    ".write",
    "full_control",
    "cloud-platform",
    "admin.datatransfer",
)

#: Scopes explicitly known to grant write access. Belt and braces alongside the
#: allowlist, so a typo cannot quietly widen access.
GOOGLE_FORBIDDEN_SCOPES: frozenset[str] = frozenset(
    {
        f"{BASE}admin.directory.user",
        f"{BASE}admin.directory.group",
        f"{BASE}admin.directory.rolemanagement",
        f"{BASE}admin.directory.domain",
        f"{BASE}drive",
        f"{BASE}drive.file",
        f"{BASE}cloud-platform",
        f"{BASE}cloud-identity.policies",
        f"{BASE}admin.directory.customer",
    }
)


class ScopeViolation(RuntimeError):
    """Raised when a scope outside the read-only allowlist is requested."""


def assert_read_only(scopes: list[str] | tuple[str, ...]) -> None:
    """Validate a requested scope set. Raises rather than filtering.

    Silently dropping a bad scope would let a caller believe it had access it
    does not have, and would hide the mistake. Failing loudly is correct here.
    """
    if not scopes:
        raise ScopeViolation("No scopes requested; refusing to authenticate.")

    for scope in scopes:
        normalized = scope.strip()
        if normalized in GOOGLE_FORBIDDEN_SCOPES:
            raise ScopeViolation(f"Scope {normalized!r} grants write access and is forbidden by policy.")
        if any(marker in normalized for marker in _WRITE_MARKERS):
            raise ScopeViolation(f"Scope {normalized!r} matches a write marker and is forbidden by policy.")
        if normalized not in GOOGLE_READONLY_SCOPES:
            raise ScopeViolation(
                f"Scope {normalized!r} is not on the read-only allowlist. "
                "Add it to GOOGLE_READONLY_SCOPES only after confirming it cannot mutate state."
            )


#: Allowlisted scopes requested in a token of their own, only by the collector
#: that needs them. Google refuses a delegated token outright if any requested
#: scope is not in the client's delegation entry, so a scope in the main token
#: is effectively mandatory: one client who has not granted it gets no
#: assessment at all. An optional scope's absence degrades its own check only.
GOOGLE_OPTIONAL_SCOPES: frozenset[str] = frozenset(
    {
        f"{BASE}cloud-identity.policies.readonly",
        f"{BASE}admin.directory.customer.readonly",
    }
)


#: Allowlisted scopes that are NOT read-only, with the reason each is needed.
#: The report names every one of these it used, in these words: a client reading
#: "read-only scopes" above a list containing one of them would rightly stop
#: trusting the rest of the page. Every allowlisted scope without ".readonly"
#: must appear here (tests/security/test_scope_claims.py).
SCOPE_CAVEATS: dict[str, str] = {
    f"{BASE}admin.directory.user.security": (
        "the only scope Google provides for listing the third-party applications each person "
        "has authorized. It would also permit revoking those authorizations and signing people "
        "out; the tool does neither."
    ),
}


def write_capable(scopes: list[str] | tuple[str, ...]) -> list[tuple[str, str]]:
    """(scope, reason) for each scope in `scopes` that is not read-only."""
    return [
        (s, SCOPE_CAVEATS.get(s, "not a read-only scope.")) for s in scopes if not s.endswith(".readonly")
    ]


def sorted_scopes() -> tuple[str, ...]:
    """The core scopes, in the main token. Deterministic; recorded in every snapshot."""
    return tuple(sorted(GOOGLE_READONLY_SCOPES - GOOGLE_OPTIONAL_SCOPES))


def optional_scopes() -> tuple[str, ...]:
    return tuple(sorted(GOOGLE_OPTIONAL_SCOPES & GOOGLE_READONLY_SCOPES))
