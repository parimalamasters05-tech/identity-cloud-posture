"""Freeze a live snapshot into an offline fixture set.

The brief's week-3 rule tests run against a frozen copy of the dev tenant. A
fixture set is shared far more widely than a snapshot -- it sits in the
repository, in CI logs, in the Docker image -- so nothing identifying survives
the freeze: emails, names, domains, directory IDs, file names and org unit
paths are replaced with stable aliases, consistently across every artifact so
that joins (a grant's user, a role's assignee) still resolve.

What is kept is exactly what the rules need: flags, timestamps, scopes, client
IDs (first-party detection is by client ID), app names, role privileges and
policy values.

After replacing, every original identifying value is searched for in the
output. If one survives -- a field this module does not know about, a name
inside an app title -- nothing is written. A leak check that only warns would
be a leak.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from icp.models.snapshot import Snapshot

#: Written beside the artifact files; the leading underscore keeps it out of the
#: artifact set when the fixture is loaded.
MANIFEST_NAME = "_frozen.json"
ALIAS_DOMAIN = "tenant.example"

_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

#: Name fragments too generic to prove a leak ("Admin Test1" would otherwise
#: match the system role "Super Admin").
_GENERIC_TOKENS = frozenset(
    {
        "admin",
        "administrator",
        "test",
        "user",
        "users",
        "group",
        "account",
        "service",
        "super",
        "team",
        "staff",
        "google",
        "workspace",
        "support",
        "info",
        "office",
        "mail",
        "demo",
    }
)
#: A real name shaped like one of our aliases ("user01" on a test account) is not
#: identifying, and would otherwise match the alias that replaced it.
_ALIAS_SHAPED = re.compile(r"^(admin|user|group|unit|external|domain|policy|item|role)\d*$")


class FreezeLeak(Exception):
    """An identifying value survived pseudonymization; nothing was written."""


@dataclass
class _Aliases:
    """Real value -> alias, built once and applied to every string."""

    exact: dict[str, str] = field(default_factory=dict)
    domains: dict[str, str] = field(default_factory=dict)
    emails: dict[str, str] = field(default_factory=dict)
    #: Values the leak scan must not find in the output.
    sensitive: set[str] = field(default_factory=set)
    #: Name fragments searched for as substrings (they hide inside file names).
    name_tokens: set[str] = field(default_factory=set)

    def domain(self, real: str) -> str:
        real = real.lower()
        if real not in self.domains:
            self.domains[real] = (
                ALIAS_DOMAIN if not self.domains else f"domain{len(self.domains) + 1}.example"
            )
            self.sensitive.add(real)
        return self.domains[real]

    def email(self, real: str, local_alias: str | None = None) -> str:
        key = real.lower()
        if key not in self.emails:
            _, _, dom = key.partition("@")
            alias_local = local_alias or f"external{len(self.emails) + 1:02d}"
            self.emails[key] = f"{alias_local}@{self.domain(dom)}"
            self.sensitive.add(key)
        return self.emails[key]

    def name(self, real: str, alias: str) -> str:
        if real:
            self.exact[real] = alias
            self.sensitive.add(real.lower())
            self.name_tokens |= {
                t
                for t in re.split(r"[\s._-]+", real.lower())
                if len(t) >= 4 and t.isalpha() and t not in _GENERIC_TOKENS and not _ALIAS_SHAPED.match(t)
            }
        return alias

    def ident(self, real: Any, alias: str) -> str:
        if real not in (None, ""):
            self.exact[str(real)] = alias
            if len(str(real)) >= 6:  # "/" and "1" are not identifying
                self.sensitive.add(str(real).lower())
        return alias

    # -- application -------------------------------------------------------------

    def apply(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: self.apply(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.apply(v) for v in value]
        if isinstance(value, str):
            return self._string(value)
        return value

    def _string(self, value: str) -> str:
        if value in self.exact:
            return self.exact[value]
        out = _EMAIL.sub(lambda m: self.email(m.group(0)), value)
        for real, alias in self.domains.items():
            out = re.sub(re.escape(real), alias, out, flags=re.IGNORECASE)
        return out


@dataclass(frozen=True)
class FreezeResult:
    out_dir: Path
    files: tuple[Path, ...]
    manifest: dict[str, Any]


def freeze(snapshot: Snapshot, out_dir: Path) -> FreezeResult:
    """Write `snapshot` as a pseudonymized fixture set in `out_dir`.

    Raises FreezeLeak (and writes nothing) if any identifying value survives.
    """
    aliases = _build_aliases(snapshot)
    artifacts = {name: aliases.apply(payload) for name, payload in snapshot.artifacts.items()}
    errors = [{**e.model_dump(mode="json"), "message": aliases.apply(e.message)} for e in snapshot.errors]
    manifest = {
        "note": (
            "Frozen, pseudonymized copy of a live snapshot. Regenerate with "
            "`icp freeze-fixtures`; never edit by hand."
        ),
        "source_snapshot_id": snapshot.snapshot_id,
        "source_schema_version": snapshot.schema_version,
        "tool_version": snapshot.tool_version,
        "frozen_at": datetime.now(UTC).isoformat(),
        "started_at": snapshot.started_at.isoformat() if snapshot.started_at else None,
        "collected_at": snapshot.collected_at.isoformat(),
        "scopes_used": list(snapshot.scopes_used),
        "scopes_refused": list(snapshot.scopes_refused),
        "partial": aliases.apply(dict(snapshot.partial)),
        "errors": errors,
        "pseudonymized": {
            "alias_domain": ALIAS_DOMAIN,
            "emails": len(aliases.emails),
            "domains": len(aliases.domains),
        },
    }

    rendered = {
        f"{name.replace('.', '__')}.json": json.dumps(payload, indent=2)
        for name, payload in artifacts.items()
    }
    rendered[MANIFEST_NAME] = json.dumps(manifest, indent=2)
    _assert_no_leak(rendered, aliases)

    out_dir.mkdir(parents=True, exist_ok=True)
    # A previous freeze's artifact that this snapshot lacks would otherwise be
    # loaded alongside the new ones, as if collected together.
    for stale in out_dir.glob("*.json"):
        if stale.name not in rendered:
            stale.unlink()
    files = []
    for filename, text in sorted(rendered.items()):
        path = out_dir / filename
        path.write_text(text + "\n", encoding="utf-8")
        files.append(path)
    return FreezeResult(out_dir=out_dir, files=tuple(files), manifest=manifest)


def read_manifest(fixture_dir: Path) -> dict[str, Any] | None:
    path = fixture_dir / MANIFEST_NAME
    return json.loads(path.read_text("utf-8")) if path.exists() else None


# -- alias construction ---------------------------------------------------------


def _build_aliases(snapshot: Snapshot) -> _Aliases:
    aliases = _Aliases()
    art = snapshot.artifacts

    # Primary domain first, so it is the one that becomes ALIAS_DOMAIN.
    domains = (art.get("google.drive_settings") or {}).get("domains", []) or []
    for d in sorted(domains, key=lambda d: not d.get("isPrimary")):
        if d.get("domainName"):
            aliases.domain(d["domainName"])

    # The organization's own name, and its domain in case the domains listing
    # was not collected. Both are then in the leak scan like any other value.
    customer = art.get("google.customer") or {}
    if customer.get("customer_domain"):
        aliases.domain(customer["customer_domain"])
    org_name = customer.get("organization_name") or ""
    # A profile whose name is just the domain (the dev tenant's is) must take
    # the domain's alias; an exact-name alias would overwrite the domain
    # everywhere it appears, and the frozen tenant's domain became
    # "Test Organization".
    if org_name.strip().lower() not in aliases.domains:
        aliases.name(org_name, "Test Organization")

    # Users: sorted by ID so aliases are stable across freezes of the same tenant.
    users = sorted(art.get("google.users") or [], key=lambda u: str(u.get("id")))
    counts = {"admin": 0, "user": 0}
    for i, u in enumerate(users, 1):
        kind = "admin" if u.get("isAdmin") else "user"
        counts[kind] += 1
        n = counts[kind]
        if u.get("primaryEmail"):
            aliases.email(u["primaryEmail"], local_alias=f"{kind}{n:02d}")
        aliases.name((u.get("name") or {}).get("fullName", ""), f"{kind.title()} {n:02d}")
        aliases.ident(u.get("id"), f"9{i:020d}")

    org_units = sorted({u.get("orgUnitPath") for u in users if u.get("orgUnitPath") not in (None, "/")})
    for i, path in enumerate(org_units, 1):
        # Whole values only, like file names. Department names are ordinary
        # words: "/Test-Locked" once matched Google's own permission name
        # GROUPS_MANAGE_LOCKED_LABEL in the roles listing, and "Finance" or
        # "Sales" would do the same. Word-by-word scanning is for people's names.
        aliases.ident(path, f"/unit{i:02d}")
        aliases.ident(path.rsplit("/", 1)[-1], f"unit{i:02d}")

    for i, g in enumerate(sorted(art.get("google.groups") or [], key=lambda g: str(g.get("id"))), 1):
        if g.get("email"):
            aliases.email(g["email"], local_alias=f"group{i:02d}")
        # Group and custom-role names are replaced and checked as whole values,
        # like departments and file names: they are the organization's own
        # vocabulary ("External Sharing Admins"), and their words turn up in
        # Google's own setting and permission names. Only people's names are
        # scanned word by word.
        aliases.ident(g.get("name"), f"Group {i:02d}")
        aliases.ident(g.get("id"), f"group-id-{i:02d}")
        aliases.ident(g.get("description"), "")

    custom = [r for r in art.get("google.roles") or [] if not r.get("isSystemRole")]
    for i, r in enumerate(sorted(custom, key=lambda r: str(r.get("roleId"))), 1):
        aliases.ident(r.get("roleName"), f"Custom role {i:02d}")
        aliases.ident(r.get("roleDescription"), "")

    # File names are replaced whole and checked whole: their words ("Grant
    # application scans") are not names, and would trip the fragment scan.
    for i, item in enumerate(art.get("google.public_drive_items") or [], 1):
        aliases.ident(item.get("name"), f"Public item {i:02d}")
        aliases.ident(item.get("id"), f"drive-item-{i:02d}")

    policies = (art.get("google.workspace_policies") or {}).get("policies", []) or []
    units = sorted({p.get("org_unit") for p in policies if p.get("org_unit")})
    for i, unit in enumerate(units, 1):
        aliases.ident(unit, f"orgUnits/unit{i:02d}")
    groups = sorted({p.get("group") for p in policies if p.get("group")})
    for i, group in enumerate(groups, 1):
        aliases.ident(group, f"groups/group{i:02d}")
    for i, p in enumerate(policies, 1):
        aliases.ident(p.get("name"), f"policies/policy{i:02d}")

    # Service accounts' client IDs are bare numbers (published apps end in
    # ".apps.googleusercontent.com" and are kept: first-party detection needs
    # them). A service account's ID and display name identify the client's own
    # cloud project -- the assessment's service account shows up in the token
    # log on every run -- so both are replaced.
    token_log = (art.get("google.token_activity") or {}).get("apps", []) or []
    grants = (art.get("google.oauth_tokens") or {}).get("grants", []) or []
    numeric = sorted(
        {str(r.get("client_id")) for r in token_log if str(r.get("client_id", "")).isdigit()}
        | {str(g.get("clientId")) for g in grants if str(g.get("clientId", "")).isdigit()}
    )
    for i, client_id in enumerate(numeric, 1):
        # Prefix 8: real Google IDs start with 1, and user aliases use 9 -- an
        # alias equal to some real ID would read as that ID leaking.
        aliases.ident(client_id, f"8{i:020d}")
        for name in {r.get("app_name") for r in token_log if str(r.get("client_id")) == client_id} | {
            g.get("displayText") for g in grants if str(g.get("clientId")) == client_id
        }:
            aliases.ident(name, f"Service account {i:02d}")

    # Every email anywhere else (drive owners, grants, MFA report) is caught by
    # the regex pass in `apply`; only its domain has to be known, and unknown
    # domains get an alias on first sight.
    return aliases


def _assert_no_leak(rendered: dict[str, str], aliases: _Aliases) -> None:
    for filename, text in rendered.items():
        lowered = text.lower()
        for value in aliases.sensitive:
            if value and value in lowered:
                raise FreezeLeak(
                    f"{filename} still contains an identifying value after pseudonymization "
                    f"({len(value)} characters). Nothing was written. Extend "
                    "icp.storage.freeze to alias the field it appears in."
                )
        for token in aliases.name_tokens:
            if token in lowered:
                raise FreezeLeak(
                    f"{filename} still contains part of a person's or unit's name. Nothing was "
                    "written. Extend icp.storage.freeze to alias the field it appears in."
                )
