"""Executive summary generation.

Written for a director or board member who will read one page and nothing else.
Prose, not bullet fragments. No acronyms that are not expanded. No sentence that
requires knowing what OAuth is.

Deliberately template-driven rather than model-generated: the same tenant must
produce the same words every time, and the assessor has to be able to stand
behind every sentence in a live walkthrough.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from icp.models.enums import CheckFamily, Severity
from icp.models.finding import Finding
from icp.normalizers.base import NormalizedTenant
from icp.reporting.plain import count, duration, lower_first, verb
from icp.reporting.platform_text import for_platform
from icp.reporting.remediation import RemediationLibrary
from icp.risk.ranking import posture_rating, rank

#: Plain-language framing per check family, for the headline risk paragraphs.
_FAMILY_FRAMING = {
    CheckFamily.MFA_COVERAGE: (
        "accounts that can be accessed with a password alone",
        "A stolen or reused password is the most common way an organization this size is "
        "broken into. A second step at sign-in stops almost all of it.",
    ),
    CheckFamily.ADMIN_ROLE_SPRAWL: (
        "more people holding full administrative control than the organization needs",
        "Every administrator account is a complete set of keys. The more that exist, the "
        "more opportunities there are for one to be misused or stolen.",
    ),
    CheckFamily.STALE_ACCOUNTS: (
        "accounts that are still active but nobody is using",
        "Unused accounts keep working indefinitely. Because nobody watches them, unusual "
        "activity on them goes unnoticed.",
    ),
    CheckFamily.SERVICE_ACCOUNT_PRIVILEGE: (
        "software connections holding administrative authority",
        "These connections act on their own, without anyone signing in. If the vendor is "
        "compromised, that access is compromised with them.",
    ),
    CheckFamily.EXTERNAL_SHARING: (
        "files that can be opened by anyone holding a link",
        "Links get forwarded and saved, and keep working after the person who shared them has left.",
    ),
    CheckFamily.LOGGING_READINESS: (
        "gaps in the records needed to investigate an incident",
        "Without these records, working out what happened after an incident becomes "
        "guesswork, and insurers and funders will ask.",
    ),
    CheckFamily.OAUTH_GRANTS: (
        "outside applications that staff have connected to organization data",
        "Each of these was approved by someone at some point and never revisited. They "
        "keep their access after password changes and after staff leave.",
    ),
}


#: Rules whose plain-language framing differs from the rest of their family.
_RULE_FRAMING = {
    "GWS-SVC-003": (
        "administrator logins left behind in developer tools",
        "A command-line login stays valid on that computer until someone revokes it. Anyone "
        "who gets the computer, or a copy of its files, inherits the administrator's access.",
    ),
}


def _framing(finding: Finding) -> tuple[str, str]:
    return _RULE_FRAMING.get(finding.rule_id) or _FAMILY_FRAMING.get(
        finding.check_family, ("a configuration weakness", "This warrants attention.")
    )


def _app(finding: Finding) -> str:
    """The application a per-app finding is about, from its title."""
    match = re.search(r"'([^']+)'", finding.title)
    return f"'{match.group(1)}'" if match else "An outside application"


#: What is wrong, in one plain sentence with the real count. Replaces the rule's
#: title in the headline, which is written for the findings table and read
#: badly as the start of a paragraph ("3 administrator accounts with no second
#: factor enrolled. In plain terms, this means...").
_WHAT: dict[str, Callable[[Finding, int], str]] = {
    "GWS-MFA-001": lambda _f, n: (
        f"{count(n, 'administrator account', start=True)} can be signed into with a password "
        "alone, with no second step such as a code sent to a phone."
    ),
    "GWS-MFA-002": lambda _f, n: (
        f"{count(n, 'staff account', start=True)} can be signed into with a password alone, "
        "with no second step such as a code sent to a phone."
    ),
    "GWS-MFA-003": lambda _f, n: (
        f"{count(n, 'administrator', start=True)} {verb(n, 'uses', 'use')} a second sign-in step "
        "that a convincing fake login page can capture."
    ),
    "GWS-ADM-001": lambda _f, n: (
        f"{count(n, 'person', 'people', start=True)} {verb(n, 'holds', 'hold')} full control of "
        "your Google Workspace, more than an organization of your size needs."
    ),
    "GWS-ADM-002": lambda _f, n: (
        f"{count(n, 'account', start=True)} with full administrative control "
        f"{verb(n, 'has', 'have')} not been used for weeks, but still {verb(n, 'works', 'work')}."
    ),
    "GWS-STA-001": lambda _f, n: (
        f"{count(n, 'account', start=True)} nobody has signed into for over three months "
        f"{verb(n, 'is', 'are')} still switched on."
    ),
    "GWS-STA-002": lambda _f, n: (
        f"{count(n, 'account', start=True)} {verb(n, 'was', 'were')} set up but never used, "
        f"and still {verb(n, 'works', 'work')}."
    ),
    "GWS-STA-003": lambda _f, n: (
        f"{count(n, 'suspended account', start=True)} still {verb(n, 'holds', 'hold')} "
        "former staff's mail and files, with no decision recorded about what happens next."
    ),
    "GWS-SVC-001": lambda f, _n: (
        f"{_app(f)}, an outside application, can manage every account in your organization."
    ),
    "GWS-SVC-002": lambda f, _n: (
        f"{_app(f)} was connected by an administrator and can reach organization-wide data."
    ),
    "GWS-SVC-003": lambda _f, _n: (
        "An administrator is still signed in to Google's technical setup tools on a computer, "
        "with full control of your Google Cloud resources."
    ),
    "GWS-SHR-001": lambda _f, n: (
        f"{count(n, 'file or folder', 'files and folders', start=True)} can be opened by anyone "
        "who has the link, with no sign-in needed."
    ),
    "GWS-SHR-002": lambda _f, _n: (
        "Staff can share files with people outside the organization without being warned first."
    ),
    "GWS-LOG-001": lambda _f, n: (
        f"{count(n, 'of the records', 'of the records', start=True)} you would need to "
        "investigate a break-in could not be read."
    ),
    "GWS-LOG-002": lambda _f, n: (
        f"{count(n, 'activity record', start=True)} that should show day-to-day activity "
        f"{verb(n, 'is', 'are')} empty."
    ),
    "GWS-OAU-001": lambda _f, n: (
        f"Outside applications can still read the mail or files of "
        f"{count(n, 'person', 'people')} who {verb(n, 'has', 'have')} left or been suspended."
    ),
    "GWS-OAU-002": lambda f, n: (
        f"{_app(f)}, an outside application, can read the mail or files of "
        f"{count(n, 'person', 'people')} in your organization."
    ),
    "GWS-OAU-003": lambda _f, n: (
        f"An application with no registered publisher can reach the data of {count(n, 'person', 'people')}."
    ),
    "GWS-OAU-004": lambda f, n: (
        f"{_app(f)} holds wide access to organization data, but only "
        f"{count(n, 'person', 'people')} {verb(n, 'uses', 'use')} it."
    ),
    "GWS-OAU-005": lambda _f, _n: (
        "Outside applications still hold access that nobody has used in over three months."
    ),
    # -- Microsoft 365 --------------------------------------------------------------
    "M365-MFA-001": lambda _f, n: (
        f"{count(n, 'administrator account', start=True)} can be signed into with a password "
        "alone, with no second step such as an approval on a phone."
    ),
    "M365-MFA-002": lambda _f, n: (
        f"{count(n, 'staff account', start=True)} can be signed into with a password alone, "
        "with no second step such as an approval on a phone."
    ),
    "M365-MFA-003": lambda _f, n: (
        f"{count(n, 'administrator', start=True)} {verb(n, 'uses', 'use')} a second sign-in step "
        "that a convincing fake login page can capture."
    ),
    "M365-MFA-004": lambda _f, _n: (
        "Nothing in the organization's settings requires a second sign-in step, so each person "
        "is protected only if they set one up themselves."
    ),
    "M365-ADM-001": lambda _f, n: (
        f"{count(n, 'person', 'people', start=True)} {verb(n, 'holds', 'hold')} full control of "
        "your Microsoft 365 organization, more than an organization of your size needs."
    ),
    "M365-STA-003": lambda _f, n: (
        f"{count(n, 'blocked account', start=True)} still {verb(n, 'holds', 'hold')} former "
        "staff's mail and files, and whatever access they gave to outside applications."
    ),
    "M365-SVC-001": lambda f, _n: (
        f"{_app(f)} can read every person's mail or files by itself, with no one signed in."
    ),
    "M365-SVC-002": lambda _f, n: (
        f"{count(n, 'application password', start=True)} {verb(n, 'stays', 'stay')} valid for "
        "years, so a copy that leaks keeps working."
    ),
    "M365-SHR-001": lambda _f, n: (
        f"{count(n, 'file or folder', 'files and folders', start=True)} can be opened by anyone "
        "who has the link, with no sign-in needed."
    ),
    "M365-SHR-002": lambda _f, _n: (
        "Any staff member can make a file open to anyone on the internet, with no sign-in needed."
    ),
    "M365-SHR-003": lambda _f, _n: (
        "Anyone in the organization, including outside guests, can invite more outside people in."
    ),
    "M365-OAU-001": lambda f, n: (
        f"{_app(f)}, an outside application, can read the mail or files of "
        f"{count(n, 'person', 'people')} in your organization."
    ),
    "M365-OAU-002": lambda _f, n: (
        f"Outside applications can still read the mail or files of "
        f"{count(n, 'person', 'people')} whose {verb(n, 'account is', 'accounts are')} blocked."
    ),
    "M365-OAU-003": lambda _f, _n: (
        "Any staff member can let an application read their mail, and no administrator sees the request."
    ),
}


def _headline_paragraph(finding: Finding, library: RemediationLibrary | None) -> str:
    n = finding.entity_count
    _, why = _framing(finding)
    what = _WHAT[finding.rule_id](finding, n) if finding.rule_id in _WHAT else f"{finding.title}."

    fix = ""
    if library is not None and finding.remediation_key in library.entries:
        action = lower_first(library.entries[finding.remediation_key].title)
        fix = f" The fix is to {action}, {duration(finding.effort_hours)} of work."

    noun = "account" if all(e.kind == "user" for e in finding.affected_entities) else "item"
    named = f" Each {noun} is named in the detailed findings." if n > 1 else ""
    return f"{what} {why}{fix}{named}"


@dataclass(frozen=True)
class HeadlineRisk:
    heading: str
    paragraph: str
    finding_ids: tuple[str, ...]


@dataclass(frozen=True)
class ExecutiveSummary:
    rating: str
    rating_explanation: str
    opening: str
    headline_risks: tuple[HeadlineRisk, ...]
    closing: str


def build(
    tenant: NormalizedTenant, findings: list[Finding], library: RemediationLibrary | None = None
) -> ExecutiveSummary:
    rating, rating_explanation = posture_rating(findings)
    actionable = [f for f in findings if f.severity != Severity.INFO]

    opening = _opening(tenant, actionable, rating)
    risks = _headline_risks(actionable, library)
    closing = _closing(actionable, tenant)

    return ExecutiveSummary(
        rating=rating,
        rating_explanation=rating_explanation,
        opening=opening,
        headline_risks=tuple(risks),
        closing=closing,
    )


def _opening(tenant: NormalizedTenant, findings: list[Finding], rating: str) -> str:
    users = len(tenant.active_users)
    apps = len({g.client_id for g in tenant.grants if not g.is_first_party})
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)

    parts = [
        f"We examined the identity and access configuration of "
        f"{for_platform(tenant.platform).environment}, covering {users} active staff accounts"
    ]
    if apps:
        parts.append(f" and {apps} connected third-party applications")
    parts.append(". The assessment was read-only: nothing in your environment was changed at any point. ")

    if critical:
        parts.append(
            f"We found {critical} issue{'s' if critical != 1 else ''} that we would ask you to "
            f"address this week, and {high} further significant one{'s' if high != 1 else ''}. "
        )
    elif high:
        parts.append(
            f"We found no issues requiring emergency action, and {high} significant "
            f"issue{'s' if high != 1 else ''} worth scheduling in the next month. "
        )
    else:
        parts.append("We found no critical or high-severity issues in the areas we examined. ")

    parts.append(f"Our overall assessment of your current position is: {rating}.")
    return "".join(parts)


def _headline_risks(
    findings: list[Finding], library: RemediationLibrary | None = None
) -> list[HeadlineRisk]:
    """The three risks the director should remember after putting the report down.

    Picked from distinct check families rather than the top three by score: three
    variations of the same problem is one headline, not three.

    Ordered by severity first, unlike the action plan. The plan answers "what
    should I do next hour", where a cheap medium fix can rightly come first; the
    board asks "what is most dangerous", and a medium above a high reads as an
    error.
    """
    ranked = sorted(
        rank(findings, dedupe_by_action=True),
        key=lambda e: (-e.finding.severity.rank, -e.finding.risk_score, e.finding.finding_id),
    )
    chosen: list[HeadlineRisk] = []
    seen: set[CheckFamily] = set()

    for entry in ranked:
        finding = entry.finding
        if finding.check_family in seen:
            continue
        seen.add(finding.check_family)

        chosen.append(
            HeadlineRisk(
                heading=_heading_for(finding),
                paragraph=_headline_paragraph(finding, library),
                finding_ids=(finding.finding_id,),
            )
        )
        if len(chosen) == 3:
            break

    return chosen


def _heading_for(finding: Finding) -> str:
    subject, _ = _framing(finding)
    return subject[0].upper() + subject[1:]


def _closing(findings: list[Finding], tenant: NormalizedTenant) -> str:
    plan = rank(findings, limit=10, dedupe_by_action=True)
    total_hours = sum(e.finding.effort_hours for e in plan)
    # The organization profile only names the cover; its absence is not a gap.
    degraded = [c for c in tenant.coverage.get("degraded_collectors") or [] if c != "google.customer"]
    n = len(plan)
    items = "one item" if n == 1 else f"{n} items"
    all_of = "it" if n == 1 else f"all {n}"

    text = (
        f"The priority action plan on the following page lists {items} to fix, most serious "
        f"first; among equally serious items, the quickest come first. Completing {all_of} is "
        f"{duration(total_hours)} of administrative work."
    )
    if degraded:
        text += (
            " Note that parts of this assessment could not be completed because some data was "
            "not accessible; those areas are listed explicitly and should not be read as having "
            "passed."
        )
    return text
