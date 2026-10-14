"""Platform-specific report wording, in one place.

The report's structure, scoring and editorial standard are shared; only the
nouns change: which console, which log, which permissions. The Google text
here is the week-4 wording moved verbatim (the Google report must not change
by a word); the Microsoft text was written for week 5.

Also the access claims. Google read-only scopes end in `.readonly`; Microsoft
Graph read-only permissions do not (`User.Read.All`). Judging Graph names by
the Google rule once printed "Not a read-only scope" against all nine
read-only permissions, in the section a skeptical reader checks first.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from icp.models.enums import CheckFamily, Platform
from icp.security.scopes import write_capable as google_write_capable


@dataclass(frozen=True)
class PlatformText:
    name: str
    environment: str
    console: str
    examined: tuple[str, ...]
    not_examined: tuple[str, ...]
    method_opening: str
    retrieval: str
    permissions_heading: str
    permission_noun: str
    audit_log: str
    licence_note: str
    anonymous_label: str
    #: (permission, reason) for permissions that are not read-only.
    write_capable: Callable[[tuple[str, ...]], list[tuple[str, str]]]
    #: (permission, reason) for read-only permissions that could read content.
    content_capable: Callable[[tuple[str, ...]], list[tuple[str, str]]] = lambda _p: []
    family_titles: dict[CheckFamily, str] = field(default_factory=dict)
    #: Said after the request count, e.g. the sign-in request Microsoft needs.
    request_note: str = ""
    cover_name_source: str = ""
    #: Replaces the request-count paragraph under "Read-only verification",
    #: for a platform this tool does not contact itself (AWS, read by Prowler).
    verification: str = ""

    @property
    def permission_nouns(self) -> str:
        """'scopes', 'permissions', 'policies'."""
        noun = self.permission_noun
        return noun[:-1] + "ies" if noun.endswith("y") else noun + "s"


GOOGLE = PlatformText(
    name="Google Workspace",
    environment="your Google Workspace environment",
    console="the Google Admin console",
    examined=(
        "Your Google Workspace staff directory: accounts, groups and departments",
        "Who holds administrator rights, and which rights",
        "Whether each account uses two-step verification, and where Google reports it, which kind",
        "Outside applications that staff have connected to their accounts",
        "When each application was connected and last used, from Google's own records",
        "Drive files and folders that anyone with the link can open",
        "Drive's settings for sharing outside the organization, where readable",
        "Whether the records needed to investigate an incident are being kept",
    ),
    not_examined=(
        "The contents of any email, document, or file. Settings and account details only.",
        "Laptops, phones, networks, or anything outside Google Workspace",
        "Any attempt to break in, test passwords, or exploit a weakness",
        "Ongoing monitoring: this is a snapshot of one moment",
        "Formal certification or attestation against any framework",
    ),
    method_opening=(
        "Read-only. Settings were read through Google's official administrative interfaces, "
        "under a signed authorization letter."
    ),
    retrieval=(
        "Configuration was retrieved through Google's official administrative APIs, using delegated "
        "credentials limited to the scopes listed below."
    ),
    permissions_heading="Scopes used",
    permission_noun="scope",
    audit_log="your own admin audit log",
    licence_note=(
        "Some Google reporting surfaces depend on your licence tier. Where data was unavailable, "
        "it is recorded as a coverage note rather than omitted."
    ),
    anonymous_label="not registered with Google",
    write_capable=lambda scopes: google_write_capable(scopes),
    family_titles={CheckFamily.MFA_COVERAGE: "Two-step verification coverage"},
    cover_name_source="the Google Workspace account profile",
)


_GRAPH_CONTENT_CAVEATS = {
    "Sites.Read.All": (
        "Microsoft offers no permission that lists who a OneDrive or SharePoint file is shared with "
        "without also allowing its contents to be read. The tool asks only for names and sharing "
        "links, and refuses, before sending, any request for a file's contents."
    ),
    "Files.Read.All": "as for Sites.Read.All: the tool reads sharing details only and refuses any content request.",
}


def _graph_write_capable(permissions: tuple[str, ...]) -> list[tuple[str, str]]:
    """Graph permissions that can change something: anything not plainly `.Read`."""
    return [
        (p, "not a read-only permission.")
        for p in permissions
        if ".Read" not in p or "ReadWrite" in p or p.endswith((".Write", ".Send"))
    ]


MICROSOFT = PlatformText(
    name="Microsoft 365",
    environment="your Microsoft 365 environment",
    console="the Microsoft 365 and Entra admin centers",
    examined=(
        "Your Microsoft 365 staff directory: members, guests and groups",
        "Who holds administrator roles, and which roles",
        "Which sign-in methods each account has registered, and whether any can resist phishing",
        "Whether the organization requires a second sign-in step (security defaults and Conditional Access)",
        "Outside applications that staff, or administrators on everyone's behalf, have given access to",
        "Applications that can reach data on their own, and how long their secrets stay valid",
        "OneDrive files that anyone with the link can open, and the sharing settings behind them",
        "Whether the sign-in and audit logs needed to investigate an incident are available",
    ),
    not_examined=(
        "The contents of any email, document, or file. Settings and account details only.",
        "Laptops, phones, networks, or anything outside Microsoft 365",
        "Any attempt to break in, test passwords, or exploit a weakness",
        "Ongoing monitoring: this is a snapshot of one moment",
        "Formal certification or attestation against any framework",
    ),
    method_opening=(
        "Read-only. Settings were read through Microsoft Graph, Microsoft's official administrative "
        "interface, under a signed authorization letter."
    ),
    retrieval=(
        "Configuration was retrieved through Microsoft Graph, Microsoft's official administrative API, "
        "by an application registration that signs in with a certificate and holds only the "
        "permissions listed below."
    ),
    permissions_heading="Permissions used",
    permission_noun="permission",
    audit_log="your Microsoft Entra audit log (Entra admin center > Entra ID > Monitoring & health > Audit logs)",
    licence_note=(
        "Some Microsoft reporting depends on your licence; sign-in logs and last sign-in times, for "
        "example, need Microsoft Entra ID P1. Where data was unavailable, it is recorded as a "
        "coverage note rather than omitted."
    ),
    anonymous_label="no verified publisher",
    write_capable=_graph_write_capable,
    content_capable=lambda permissions: [
        (p, _GRAPH_CONTENT_CAVEATS[p]) for p in permissions if p in _GRAPH_CONTENT_CAVEATS
    ],
    family_titles={CheckFamily.MFA_COVERAGE: "Second sign-in step coverage"},
    request_note=(
        " In addition, one sign-in request was sent to Microsoft's login service to obtain the "
        "access token; it changes nothing in your organization."
    ),
    cover_name_source="the Microsoft 365 organization profile",
)


#: AWS is read by Prowler, an open-source scanner, not by this tool's own
#: collectors (the brief: wrap existing tooling, do not rebuild it). The wording
#: says so: the read-only claim rests on the role's policies and on CloudTrail,
#: not on this tool's request guard, which never contacts AWS.
AWS = PlatformText(
    name="AWS",
    environment="your AWS account",
    console="the AWS Management Console",
    examined=(
        "The sign-in protection on the account's root user and on each person's AWS login",
        "Which users, groups and roles hold full administrative rights",
        "Logins and access keys that have not been used for a long time, and keys never replaced",
        "Roles that other AWS accounts or services are allowed to use",
        "Storage buckets that the public can read or write, and the settings that should prevent it",
        "Whether the activity records needed to investigate an incident are being kept",
    ),
    not_examined=(
        "The contents of any file or database. Settings and account details only.",
        "Servers, networks, application code, or anything outside identity and storage exposure",
        "Any attempt to break in, test passwords, or exploit a weakness",
        "Ongoing monitoring: this is a snapshot of one moment",
        "Formal certification or attestation against any framework",
    ),
    method_opening=(
        "Read-only. Settings were read with Prowler, an open-source assessment tool, through a "
        "role limited to AWS's own read-only audit policies, under a signed authorization letter."
    ),
    retrieval=(
        "Configuration was read by Prowler, an open-source assessment tool, using a role in your "
        "account that holds only the two AWS-managed policies listed below. This report's tool "
        "then read Prowler's results; it did not contact AWS itself."
    ),
    permissions_heading="Policies on the assessment role",
    permission_noun="policy",
    audit_log="AWS CloudTrail (CloudTrail > Event history, filtered by the assessment role's name)",
    licence_note=(
        "Only identity and storage-exposure settings were examined in AWS; this is not a full "
        "review of the account. A check Prowler did not run is recorded as a coverage note "
        "rather than omitted."
    ),
    anonymous_label="",
    write_capable=lambda _policies: [],
    family_titles={
        CheckFamily.MFA_COVERAGE: "Second sign-in step coverage",
        CheckFamily.EXTERNAL_SHARING: "Public storage exposure",
        CheckFamily.OAUTH_GRANTS: "Access given to other accounts",
    },
    cover_name_source="the AWS account alias",
    verification=(
        "This report's tool made no requests to AWS: it read the results file Prowler wrote. "
        "Prowler read the account through the assessment role, whose two AWS-managed policies "
        "allow reading and listing only, so AWS itself would have refused any attempt to change "
        "something. We recommend you confirm this independently in"
    ),
)

_BY_PLATFORM = {Platform.MICROSOFT_365: MICROSOFT, Platform.AWS: AWS}


def for_platform(platform: Platform) -> PlatformText:
    return _BY_PLATFORM.get(platform, GOOGLE)


def _join(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def combined(platforms: list[Platform]) -> PlatformText:
    """Wording for one report covering several platforms (week 5).

    Page-one text is platform-neutral, because two full "what we examined"
    lists do not fit on a cover; each platform's own access details are given
    in the methodology, one block per platform.
    """
    from dataclasses import replace

    texts = [for_platform(p) for p in platforms]
    names = _join([t.name for t in texts])
    # AWS has no staff directory, and is read by Prowler: say so on the cover
    # rather than let the Workspace and Microsoft wording claim it.
    with_aws = Platform.AWS in platforms
    staffed = _join([t.name for t in texts if t is not AWS]) if with_aws else names
    aws_lines = (
        ("In AWS: the root user, users and roles with full control, and unused or old access keys",)
        if with_aws
        else ()
    )
    return replace(
        texts[0],
        name=names,
        environment=f"your {names} environments",
        console=_join([t.console for t in texts]),
        examined=(
            f"Your staff directories in {staffed}: accounts, guests and groups",
            "Who holds administrator rights, and which rights",
            "Whether each account uses a second sign-in step, and whether it can resist phishing",
            "Outside applications that staff or administrators have given access to",
            "Applications that hold access on their own, and how they sign in",
            *aws_lines,
            (
                "Files, folders and storage buckets that the public can open, and the settings behind them"
                if with_aws
                else "Files and folders that anyone with the link can open, and the sharing settings behind them"
            ),
            "Whether the records needed to investigate an incident are being kept",
        ),
        not_examined=(
            "The contents of any email, document, or file. Settings and account details only.",
            f"Laptops, phones, networks, or anything outside {names}",
            "Any attempt to break in, test passwords, or exploit a weakness",
            "Ongoing monitoring: this is a snapshot of one moment",
            "Formal certification or attestation against any framework",
        ),
        method_opening=(
            f"Read-only. Settings were read through the official administrative interfaces of {names}, "
            "under a signed authorization letter."
            + (
                " In AWS the reading was done by Prowler, an open-source assessment tool, through a "
                "role limited to AWS's own read-only audit policies."
                if with_aws
                else ""
            )
        ),
        family_titles={CheckFamily.MFA_COVERAGE: "Second sign-in step coverage"},
        cover_name_source="",
    )
