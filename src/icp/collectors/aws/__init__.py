"""AWS: import Prowler's results into a snapshot.

The brief handles AWS by wrapping existing free tooling rather than building
collectors. Prowler, run separately through a read-only role, reads the
account and writes its results as OCSF JSON; this module turns that file into
the same kind of snapshot the other platforms produce.

This tool therefore never contacts AWS. Nothing here opens a network
connection: the only input is a file on disk.

Only what a finding needs is kept, for the checks in the check map: the check,
pass or fail, and which resource. Prowler's full output (every check's
description, risk text and compliance mappings, for every resource) is not
copied into the snapshot.
"""

from __future__ import annotations

import json
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from icp.models.enums import Assessability, Platform
from icp.models.snapshot import CollectionError, Snapshot
from icp.risk.prowler_map import ProwlerMap
from icp.risk.prowler_map import load as load_map

#: The AWS-managed policies the assessment role is set up with (the brief, §5).
#: Declared, not read back: Prowler's output does not say which policies the
#: role holds, so the report words this as how the role was set up.
ROLE_POLICIES: tuple[str, ...] = ("SecurityAudit", "ViewOnlyAccess")

_STATUSES = frozenset({"PASS", "FAIL", "MANUAL", "MUTED"})


class ProwlerImportError(ValueError):
    """The file is not Prowler OCSF output this tool can use."""


def _when(item: dict[str, Any]) -> datetime | None:
    stamp = item.get("time_dt")
    if isinstance(stamp, str):
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    epoch = item.get("time")
    if isinstance(epoch, int | float):
        # OCSF allows seconds or milliseconds.
        return datetime.fromtimestamp(epoch / 1000 if epoch > 1e11 else epoch, tz=UTC)
    return None


def _row(item: dict[str, Any]) -> dict[str, Any]:
    resource = (item.get("resources") or [{}])[0] or {}
    return {
        "check_id": str((item.get("metadata") or {}).get("event_code") or ""),
        "status": str(item.get("status_code") or "").upper(),
        "resource_uid": str(resource.get("uid") or ""),
        "resource_name": str(resource.get("name") or ""),
        "resource_type": str(resource.get("type") or ""),
        "region": str(resource.get("region") or (item.get("cloud") or {}).get("region") or ""),
        # Prowler's own one-line reason, kept as the technical record behind
        # the plain sentence the report shows.
        "detail": str(item.get("status_detail") or item.get("message") or ""),
    }


#: "... is not authorized to perform: iam:GetLoginProfile on resource: ..."
_REFUSED = re.compile(r"not authorized to perform: ([A-Za-z0-9-]+:[A-Za-z0-9]+)")
_REGION = re.compile(r"\b([a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d) -- ")


def read_refusals(log_path: Path) -> dict[str, dict[str, Any]]:
    """Reads AWS refused during the scan, from Prowler's log.

    Prowler logs a refused read and carries on, and its checks then report on
    the data it did not get: seen live, an organization's service control
    policy denied iam:GetLoginProfile, and every user was reported as having
    no console password. Returns action -> {"count", "by_organization_policy"}.
    """
    refused: dict[str, dict[str, Any]] = {}
    for line in Path(log_path).read_text("utf-8", errors="replace").splitlines():
        match = _REFUSED.search(line)
        if not match:
            continue
        entry = refused.setdefault(
            match.group(1), {"count": 0, "by_organization_policy": False, "regions": []}
        )
        entry["count"] += 1
        entry["by_organization_policy"] |= "service control policy" in line
        # Prowler starts each regional error with "<region> -- ".
        region = _REGION.search(line)
        if region and region.group(1) not in entry["regions"]:
            entry["regions"] = sorted([*entry["regions"], region.group(1)])
    return dict(sorted(refused.items()))


#: Check-map service -> the prefix AWS uses for its actions.
_ACTION_PREFIX = {"accessanalyzer": "access-analyzer"}


def _not_read(service: str, denied: dict[str, dict[str, Any]] | None) -> str:
    """Why Prowler returned nothing for a whole area, as precisely as the log allows."""
    prefix = _ACTION_PREFIX.get(service, service) + ":"
    refused = sorted(a for a in (denied or {}) if a.startswith(prefix))
    if refused:
        by_policy = any((denied or {})[a]["by_organization_policy"] for a in refused)
        return (
            f"AWS refused the reads this area needs ({', '.join(refused)})"
            + (
                ", because of a policy set by the organization that manages this account "
                "(a service control policy), whatever rights the assessment role has"
                if by_policy
                else ""
            )
            + "."
        )
    return (
        "Prowler returned no result for this area. The assessment role may lack permission to "
        "read it, or these checks were not included in the run."
    )


def import_prowler(
    path: Path,
    *,
    tenant_id: str = "aws",
    account_alias: str = "",
    check_map: ProwlerMap | None = None,
    log_path: Path | None = None,
) -> Snapshot:
    """Read a Prowler `json-ocsf` file and return a snapshot.

    Raises ProwlerImportError when the file is not usable at all. A service
    Prowler returned nothing for is not an error: it is recorded so the rules
    for that service report "not assessed".
    """
    check_map = check_map or load_map()
    try:
        data = json.loads(Path(path).read_text("utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        if isinstance(exc, json.JSONDecodeError) and exc.msg == "Extra data":
            raise ProwlerImportError(
                f"{path.name} holds more than one Prowler run: Prowler adds to an existing results "
                "file instead of replacing it. Delete prowler.ocsf.json and prowler.log from the "
                "prowler-output folder and scan again."
            ) from exc
        raise ProwlerImportError(f"Could not read Prowler output {path.name}: {exc}") from exc
    if not isinstance(data, list) or not all(isinstance(i, dict) for i in data):
        raise ProwlerImportError(
            f"{path.name} is not Prowler OCSF output: expected a JSON list of findings "
            "(run Prowler with --output-formats json-ocsf)."
        )

    aws = [i for i in data if ((i.get("cloud") or {}).get("provider") or "aws").lower() == "aws"]
    accounts = sorted(
        {str(((i.get("cloud") or {}).get("account") or {}).get("uid") or "") for i in aws} - {""}
    )
    if not aws or not accounts:
        raise ProwlerImportError(f"{path.name} holds no AWS results with an account number.")
    if len(accounts) > 1:
        raise ProwlerImportError(
            f"{path.name} holds results for {len(accounts)} AWS accounts ({', '.join(accounts)}). "
            "Import one account at a time: each gets its own snapshot and report section."
        )

    wanted = set(check_map.checks)
    rows = [r for r in (_row(i) for i in aws) if r["check_id"] in wanted and r["status"] in _STATUSES]
    rows.sort(key=lambda r: (r["check_id"], r["region"], r["resource_uid"], r["status"]))

    versions = sorted(
        {str(((i.get("metadata") or {}).get("product") or {}).get("version") or "") for i in aws} - {""}
    )
    names = sorted(
        {str(((i.get("cloud") or {}).get("account") or {}).get("name") or "") for i in aws} - {""}
    )

    # A service with no result for any of its checks was not read: Prowler
    # logs an access-denied error and simply emits nothing for it.
    denied = read_refusals(log_path) if log_path else None
    errors = []
    seen = {r["check_id"] for r in rows}
    for service, checks in check_map.services.items():
        if not seen & set(checks):
            errors.append(
                CollectionError(
                    collector=f"aws.{service}",
                    assessability=Assessability.NOT_ASSESSABLE_PERMISSION,
                    message=_not_read(service, denied),
                )
            )

    times = [t for t in (_when(i) for i in aws) if t is not None]
    collected_at = max(times) if times else datetime.now(UTC)
    return Snapshot(
        snapshot_id=f"{collected_at:%Y%m%dT%H%M%S%f}"[:-3] + "Z-" + secrets.token_hex(4),
        tenant_id=tenant_id,
        platform=Platform.AWS,
        started_at=min(times) if times else None,
        collected_at=collected_at,
        scopes_used=ROLE_POLICIES,
        artifacts={
            "aws.account": {
                "account_id": accounts[0],
                "alias": account_alias or (names[0] if names else ""),
            },
            "aws.prowler": {
                "prowler_version": versions[0] if versions else "",
                "checks_mapped": list(check_map.checks),
                "results": rows,
            },
            # None when no Prowler log was given: refusals are then unknown,
            # not absent, and the report cannot claim either way.
            "aws.denied": denied,
        },
        errors=tuple(errors),
    )
