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


def for_platform(platform: Platform) -> PlatformText:
    return MICROSOFT if platform == Platform.MICROSOFT_365 else GOOGLE
