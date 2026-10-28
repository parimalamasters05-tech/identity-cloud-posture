"""Reviewed exceptions: business context the heuristics cannot see.

Several checks fire on things that can be legitimate for a given client: more
administrators than the threshold, an emergency-access account that is meant
to sit unused, a suspended account kept for legal hold, a backup application
that needs broad access, a file that is public on purpose. Lowering confidence
does not settle those; the client's decision does.

An exception is that decision, written down: which rule, which stable entity
ID, who owns it, why, what compensates, and until when. It never hides the
observation. A finding wholly covered by exceptions leaves the action plan and
the rating, and is listed with every exception under "Accepted exceptions"; a
partly covered one stays, with the excepted items marked. An expired
exception stops applying and is listed as expired; one that matched nothing
is listed too, so stale exceptions surface instead of piling up.

The file is per engagement (ICP_EXCEPTIONS_FILE) and names the client's
accounts and applications, so it is client data: never committed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from icp.models.finding import AcceptedException, Finding

#: Every field is required: an exception without an owner, a reason, a
#: compensating control or an end date is not a reviewed decision.
REQUIRED = ("rule", "entity", "owner", "rationale", "compensating_control", "approved_on", "expires")


class ExceptionsError(ValueError):
    """The exceptions file cannot be used as written."""


@dataclass
class ExceptionsReport:
    #: (exception, the finding it applies to)
    applied: list[tuple[AcceptedException, Finding]] = field(default_factory=list)
    #: Past their expiry: no longer applied, and said so.
    expired: list[AcceptedException] = field(default_factory=list)
    #: Approved for a later date: not applied yet.
    not_yet_valid: list[AcceptedException] = field(default_factory=list)
    #: In force, but matched nothing in this assessment.
    unused: list[AcceptedException] = field(default_factory=list)


def load(path: Path) -> list[AcceptedException]:
    """Read and check the exceptions file. Refuses rather than guesses."""
    try:
        data = yaml.safe_load(Path(path).read_text("utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ExceptionsError(f"Cannot read the exceptions file {path}: {exc}") from exc
    entries = data.get("exceptions") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ExceptionsError(f"{path}: expected a list under 'exceptions:'.")
    out: list[AcceptedException] = []
    for n, entry in enumerate(entries, 1):
        out.append(_one(path, n, entry))
    return out


def _one(path: Path, n: int, entry: Any) -> AcceptedException:
    where = f"{path}, exception {n}"
    if not isinstance(entry, dict):
        raise ExceptionsError(f"{where}: expected a mapping of fields.")
    missing = [k for k in REQUIRED if not str(entry.get(k) or "").strip()]
    if missing:
        raise ExceptionsError(
            f"{where}: missing {', '.join(missing)}. Every exception needs all of {', '.join(REQUIRED)}."
        )
    approved, expires = (
        _date(where, "approved_on", entry["approved_on"]),
        _date(where, "expires", entry["expires"]),
    )
    if expires <= approved:
        raise ExceptionsError(f"{where}: expires ({expires}) must be after approved_on ({approved}).")
    return AcceptedException(
        rule_id=str(entry["rule"]).strip(),
        entity=str(entry["entity"]).strip(),
        owner=str(entry["owner"]).strip(),
        rationale=str(entry["rationale"]).strip(),
        compensating_control=str(entry["compensating_control"]).strip(),
        approved_on=approved,
        expires=expires,
    )


def _date(where: str, name: str, value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise ExceptionsError(f"{where}: {name} must be a date (YYYY-MM-DD), not {value!r}.") from exc


def apply(
    findings: list[Finding], exceptions: list[AcceptedException], now: datetime
) -> tuple[list[Finding], ExceptionsReport]:
    """Attach each exception in force to the findings it matches.

    In force: approved on or before the assessment date, and not past its
    expiry (the expiry date itself is the last day it applies). Coverage notes
    are never excepted: they say what was not assessed, not what is wrong.
    """
    today = now.date()
    report = ExceptionsReport()
    in_force = []
    for x in exceptions:
        if x.expires < today:
            report.expired.append(x)
        elif x.approved_on > today:
            report.not_yet_valid.append(x)
        else:
            in_force.append(x)

    used: set[int] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.rule_id.startswith("ICP-"):
            out.append(finding)
            continue
        ids = {e.id for e in finding.affected_entities}
        matched = [
            (i, x)
            for i, x in enumerate(in_force)
            if x.rule_id == finding.rule_id and (x.entity == "*" or x.entity in ids)
        ]
        if matched:
            used |= {i for i, _ in matched}
            finding = finding.model_copy(update={"exceptions": tuple(x for _, x in matched)})
            report.applied += [(x, finding) for _, x in matched]
        out.append(finding)
    report.unused = [x for i, x in enumerate(in_force) if i not in used]
    return out, report
