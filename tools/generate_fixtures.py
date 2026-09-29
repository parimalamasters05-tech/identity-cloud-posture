"""Generate the dev-tenant fixture set with deliberately planted findings.

Mirrors the week-1 seeding plan from the project brief so that the rule suite
can be tested offline against a tenant whose problems are known in advance.
Every planted finding here has a matching assertion in
`tests/rules/test_planted_findings.py`.

Regenerate with:  python tools/generate_fixtures.py
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "google"
NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
DOMAIN = "dev-icp.example"


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def days_ago(n: int) -> str:
    return iso(NOW - timedelta(days=n))


# --- planted design -----------------------------------------------------------
# 32 users:
#   3 super-admins  (1 of them with no 2SV      -> GWS-MFA-001)
#                   (1 of them dormant 120 days -> GWS-ADM-002)
#   1 delegated admin
#   6 users with no 2SV                          -> GWS-MFA-002
#   5 dormant users (>90d)                       -> GWS-STA-001
#   2 never-signed-in, created 200d ago          -> GWS-STA-002
#   2 suspended users retaining OAuth grants     -> GWS-STA-003, GWS-OAU-001
#   1 delegated admin signed in to gcloud        -> GWS-SVC-003
#   1 broad app unused for 150 days              -> GWS-OAU-005
#   sign-in log unreadable                       -> GWS-LOG-001
# Super-admins stay at 3 of 32 active (9.4%), under both ceilings, so
# GWS-ADM-001 must NOT fire; one more tips it (see test_planted_findings).
# ------------------------------------------------------------------------------

USERS: list[dict] = []


def add_user(
    idx: int,
    name: str,
    *,
    super_admin: bool = False,
    delegated: bool = False,
    mfa: bool = True,
    security_keys: int = 0,
    last_login_days: int | None = 3,
    created_days: int = 400,
    suspended: bool = False,
) -> dict:
    user = {
        "id": f"1000000000000000000{idx:02d}",
        "primaryEmail": f"{name}@{DOMAIN}",
        "name": {"fullName": name.replace(".", " ").title()},
        "suspended": suspended,
        "archived": False,
        "isAdmin": super_admin,
        "isDelegatedAdmin": delegated,
        "isEnrolledIn2Sv": mfa,
        "isEnforcedIn2Sv": mfa,
        "creationTime": days_ago(created_days),
        "lastLoginTime": days_ago(last_login_days)
        if last_login_days is not None
        else "1970-01-01T00:00:00.000Z",
        "orgUnitPath": "/",
        "agreedToTerms": True,
        "changePasswordAtNextLogin": False,
        "_security_keys": security_keys,
    }
    USERS.append(user)
    return user


# Super admins
add_user(1, "dana.reyes", super_admin=True, mfa=True, security_keys=2, last_login_days=1)
add_user(2, "sam.okafor", super_admin=True, mfa=False, last_login_days=6)  # MFA-001
add_user(3, "former.consultant", super_admin=True, mfa=True, last_login_days=120)  # ADM-002
# Delegated admin
add_user(4, "priya.menon", delegated=True, mfa=True, last_login_days=2)

# Ordinary staff, healthy
for i, name in enumerate(
    [
        "alex.tan",
        "bea.novak",
        "chris.dube",
        "dee.ali",
        "eli.park",
        "fran.mbeki",
        "gus.iversen",
        "hana.sato",
        "ivan.petrov",
        "jo.kelly",
        "kim.larsen",
        "leo.costa",
        "mia.haddad",
        "nina.oyelaran",
        "omar.said",
    ],
    start=10,
):
    add_user(i, name, mfa=True, last_login_days=(i % 7) + 1)

# No second factor
for i, name in enumerate(
    ["pat.dunne", "quinn.reilly", "rosa.mendes", "sean.byrne", "tara.singh", "umar.khan"],
    start=30,
):
    add_user(i, name, mfa=False, last_login_days=(i % 5) + 1)

# Dormant
for i, name in enumerate(["vic.nowak", "wes.olsen", "xena.abara", "yuri.baros", "zoe.carr"], start=40):
    add_user(i, name, mfa=True, last_login_days=120 + i)

# Never signed in
add_user(50, "new.starter.a", mfa=False, last_login_days=None, created_days=200)
add_user(51, "project.placeholder", mfa=False, last_login_days=None, created_days=210)

# Suspended, still holding grants
add_user(60, "departed.finance", mfa=True, last_login_days=250, suspended=True)
add_user(61, "departed.ops", mfa=True, last_login_days=300, suspended=True)


# --- roles --------------------------------------------------------------------

ROLES = [
    {
        "roleId": "10001",
        "roleName": "_SEED_ADMIN_ROLE",
        "roleDescription": "Google Workspace Super Admin",
        "isSuperAdminRole": True,
        "isSystemRole": True,
        "rolePrivileges": [{"privilegeName": "ROOT_APP_ADMIN", "serviceId": "01"}],
    },
    {
        "roleId": "10002",
        "roleName": "User Management Admin",
        "roleDescription": "Manage users",
        "isSuperAdminRole": False,
        "isSystemRole": True,
        "rolePrivileges": [{"privilegeName": "USERS_ALL", "serviceId": "01"}],
    },
]

ROLE_ASSIGNMENTS = [
    {
        "roleAssignmentId": "9001",
        "roleId": "10001",
        "assignedTo": USERS[0]["id"],
        "scopeType": "CUSTOMER",
        "assigneeType": "user",
    },
    {
        "roleAssignmentId": "9002",
        "roleId": "10001",
        "assignedTo": USERS[1]["id"],
        "scopeType": "CUSTOMER",
        "assigneeType": "user",
    },
    {
        "roleAssignmentId": "9003",
        "roleId": "10001",
        "assignedTo": USERS[2]["id"],
        "scopeType": "CUSTOMER",
        "assigneeType": "user",
    },
    {
        "roleAssignmentId": "9004",
        "roleId": "10002",
        "assignedTo": USERS[3]["id"],
        "scopeType": "CUSTOMER",
        "assigneeType": "user",
    },
]

GROUPS = [
    {
        "id": "g001",
        "email": f"all@{DOMAIN}",
        "name": "All Staff",
        "description": "",
        "directMembersCount": "32",
        "adminCreated": True,
    },
    {
        "id": "g002",
        "email": f"finance@{DOMAIN}",
        "name": "Finance",
        "description": "",
        "directMembersCount": "4",
        "adminCreated": True,
    },
]


# --- oauth grants -------------------------------------------------------------

MAIL_FULL = "https://mail.google.com/"
DRIVE_RO = "https://www.googleapis.com/auth/drive.readonly"
GMAIL_RO = "https://www.googleapis.com/auth/gmail.readonly"
ADMIN_USER = "https://www.googleapis.com/auth/admin.directory.user"
SIGN_IN = ["openid", "https://www.googleapis.com/auth/userinfo.email"]
CAL_RO = "https://www.googleapis.com/auth/calendar.readonly"


def grant(
    user: dict, client_id: str, app: str, scopes: list[str], *, anonymous=False, native=False
) -> dict:
    return {
        "clientId": client_id,
        "displayText": app,
        "anonymous": anonymous,
        "nativeApp": native,
        "scopes": scopes,
        "userKey": user["primaryEmail"],
        "userId": user["id"],
        "userSuspended": user["suspended"],
        "userArchived": False,
        "kind": "admin#directory#token",
    }


GRANTS: list[dict] = []

# Broad-scope meeting transcriber across a third of staff -> GWS-OAU-002
for user in USERS[4:16]:
    GRANTS.append(
        grant(
            user, "884411223344.apps.googleusercontent.com", "NoteTaker AI", [MAIL_FULL, DRIVE_RO, CAL_RO]
        )
    )

# Benign sign-in-only app, widely used: must NOT be flagged
for user in USERS[:20]:
    GRANTS.append(grant(user, "111222333444.apps.googleusercontent.com", "Payroll Portal", SIGN_IN))

# Admin-equivalent integration -> GWS-SVC-001
GRANTS.append(
    grant(
        USERS[0], "555666777888.apps.googleusercontent.com", "LegacySync Connector", [ADMIN_USER, DRIVE_RO]
    )
)

# Unverified/anonymous app -> GWS-OAU-003
GRANTS.append(grant(USERS[12], "999000111222.apps.googleusercontent.com", "", [GMAIL_RO], anonymous=True))

# Single-user broad-scope shadow IT -> GWS-OAU-004
GRANTS.append(grant(USERS[14], "777888999000.apps.googleusercontent.com", "InboxCleaner Pro", [MAIL_FULL]))

# Suspended users retaining grants -> GWS-OAU-001
GRANTS.append(
    grant(USERS[-2], "884411223344.apps.googleusercontent.com", "NoteTaker AI", [MAIL_FULL, DRIVE_RO])
)
GRANTS.append(
    grant(USERS[-1], "222333444555.apps.googleusercontent.com", "ExpenseTracker", [GMAIL_RO, MAIL_FULL])
)

# Delegated admin signed in to gcloud -> GWS-SVC-003, and never a third-party
# app finding (first-party by client ID). Scopes as gcloud requests them.
GRANTS.append(
    grant(
        USERS[3],
        "32555940559.apps.googleusercontent.com",
        "Google Cloud SDK",
        [
            *SIGN_IN,
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/compute",
        ],
    )
)


# --- drive, audit, mfa report -------------------------------------------------

PUBLIC_DRIVE = [
    {
        "id": "dr001",
        "name": "Board Pack 2026 (DRAFT)",
        "mimeType": "application/vnd.google-apps.folder",
        "shared": True,
        "modifiedTime": days_ago(30),
        "owners": [f"dana.reyes@{DOMAIN}"],
    },
    {
        "id": "dr002",
        "name": "Donor List - master",
        "mimeType": "application/vnd.google-apps.spreadsheet",
        "shared": True,
        "modifiedTime": days_ago(75),
        # An ordinary staff member, not the admin: the case the first Drive
        # search missed. (Suspended owners' files cannot be searched at all.)
        "owners": [f"fran.mbeki@{DOMAIN}"],
    },
    {
        "id": "dr003",
        "name": "Grant application scans",
        "mimeType": "application/vnd.google-apps.folder",
        "shared": True,
        "modifiedTime": days_ago(120),
        "owners": [f"priya.menon@{DOMAIN}"],
    },
]

AUDIT = {
    "probe_window_days": 30,
    "streams": {
        "admin": {
            "available": True,
            "event_count_sampled": 12,
            "oldest_sampled": days_ago(28),
            "newest_sampled": days_ago(2),
        },
        # Planted: the sign-in log is unreadable -> GWS-LOG-001. (Previously the
        # token log; it moved because the token log now feeds GWS-OAU-005, and
        # the fixture must not claim a log is both unreadable and read.)
        "login": {"available": False, "http_status": 403, "reason": "HttpError"},
        "token": {
            "available": True,
            "event_count_sampled": 50,
            "oldest_sampled": days_ago(28),
            "newest_sampled": days_ago(1),
        },
        "drive": {
            "available": True,
            "event_count_sampled": 50,
            "oldest_sampled": days_ago(4),
            "newest_sampled": days_ago(1),
        },
    },
}

MFA_REPORT = {
    "report_date": (NOW - timedelta(days=2)).strftime("%Y-%m-%d"),
    "entries": [
        {
            "profile_id": u["id"],
            "email": u["primaryEmail"],
            # Google's field names (accounts:num_security_keys and
            # accounts:num_passkeys_enrolled), as the collector keeps them.
            "num_security_keys": u["_security_keys"],
            "num_passkeys_enrolled": 0,
        }
        for u in USERS
    ],
}

DOMAINS = {"domains": [{"domainName": DOMAIN, "isPrimary": True, "verified": True}]}

# The organization profile, as the collector keeps it (contact details dropped).
CUSTOMER = {
    "organization_name": "Riverside Community Trust",
    "customer_domain": DOMAIN,
    "created": days_ago(900),
    "language": "en",
}


# --- token audit log ----------------------------------------------------------
# Raw events in the Reports API's shape, newest first, reduced by the real
# collector code so the fixture cannot drift from what collection produces.
# Planted: InboxCleaner Pro (kim.larsen) was authorized 170 days ago and last
# used 150 days ago -> GWS-OAU-005. Everything else broad is in use.
# Usage events are named "activity" here; the collector treats any event other
# than authorize/revoke as usage.

NOTETAKER = "884411223344.apps.googleusercontent.com"
TOKEN_EVENTS: list[dict] = []


def token_event(user: str, client_id: str, app: str, name: str, days: int) -> None:
    TOKEN_EVENTS.append(
        {
            "id": {"time": days_ago(days), "applicationName": "token"},
            "actor": {"email": f"{user}@{DOMAIN}"},
            "events": [
                {
                    "name": name,
                    "parameters": [
                        {"name": "client_id", "value": client_id},
                        {"name": "app_name", "value": app},
                        {"name": "client_type", "value": "WEB"},
                    ],
                }
            ],
        }
    )


for u in USERS[4:16]:
    token_event(u["primaryEmail"].split("@")[0], NOTETAKER, "NoteTaker AI", "activity", 2)
token_event("dana.reyes", "555666777888.apps.googleusercontent.com", "LegacySync Connector", "activity", 1)
token_event("ivan.petrov", "999000111222.apps.googleusercontent.com", "", "activity", 5)
token_event("kim.larsen", "777888999000.apps.googleusercontent.com", "InboxCleaner Pro", "activity", 150)
token_event("kim.larsen", "777888999000.apps.googleusercontent.com", "InboxCleaner Pro", "authorize", 170)
# Revoked already: history only, never a finding.
token_event("bea.novak", "333444555666.apps.googleusercontent.com", "OldSurveyTool", "revoke", 60)
# The assessment's own service account being authorized for collection.
token_event("dana.reyes", "100000000000000000099", "Posture assessment", "authorize", 0)
TOKEN_EVENTS.sort(key=lambda e: e["id"]["time"], reverse=True)


def token_activity() -> dict:
    from icp.collectors.google.token_activity import WINDOW_DAYS, summarize

    return summarize(TOKEN_EVENTS, window_start=NOW - timedelta(days=WINDOW_DAYS), truncated=False)


# Collector output shape (already filtered to the retained setting types), with
# Policy API values in their camelCase wire format.
# Planted: the top-level unit shares externally with no warning (GWS-SHR-002);
# the finance unit is locked down and must not be named in that finding.
WORKSPACE_POLICIES = {
    "policies": [
        {
            "name": "policies/fixture-sharing-root",
            "policy_type": "ADMIN",
            "setting_type": "drive_and_docs.external_sharing",
            "org_unit": "orgUnits/fixture-root",
            "group": "",
            "sort_order": 1.0,
            "value": {"externalSharingMode": "ALLOWED", "warnForExternalSharing": False},
        },
        {
            "name": "policies/fixture-sharing-finance",
            "policy_type": "ADMIN",
            "setting_type": "drive_and_docs.external_sharing",
            "org_unit": "orgUnits/fixture-finance",
            "group": "",
            "sort_order": 2.0,
            "value": {"externalSharingMode": "DISALLOWED"},
        },
        {
            "name": "policies/fixture-2sv-enrollment",
            "policy_type": "SYSTEM",
            "setting_type": "security.two_step_verification_enrollment",
            "org_unit": "orgUnits/fixture-root",
            "group": "",
            "sort_order": 1.0,
            "value": {"allowEnrollment": True},
        },
    ],
    "setting_types_found": [
        "drive_and_docs.external_sharing",
        "security.two_step_verification_enrollment",
    ],
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    clean_users = [{k: v for k, v in u.items() if not k.startswith("_")} for u in USERS]

    artifacts = {
        "google__users": clean_users,
        "google__groups": GROUPS,
        "google__roles": ROLES,
        "google__role_assignments": ROLE_ASSIGNMENTS,
        "google__mfa": MFA_REPORT,
        "google__oauth_tokens": {
            "grants": GRANTS,
            "failed_users": [],
            "users_enumerated": len(USERS),
            "users_total": len(USERS),
        },
        "google__token_activity": token_activity(),
        "google__drive_settings": DOMAINS,
        "google__customer": CUSTOMER,
        "google__workspace_policies": WORKSPACE_POLICIES,
        "google__public_drive_items": PUBLIC_DRIVE,
        "google__audit_readiness": AUDIT,
    }

    for name, payload in artifacts.items():
        (OUT / f"{name}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Wrote {len(artifacts)} fixture files to {OUT}")
    print(f"  users: {len(clean_users)}  grants: {len(GRANTS)}  public drive items: {len(PUBLIC_DRIVE)}")


if __name__ == "__main__":
    main()
