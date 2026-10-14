"""Microsoft 365 rules against a synthetic copy of the seeded dev tenant.

The artifact shapes are the collector's own output; the people and settings
mirror what was seeded on 6 Oct 2026. Each test names the planted problem it
proves is caught, or the live false result it proves is fixed.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

import pytest

from icp.models.enums import Platform
from icp.models.snapshot import Snapshot
from icp.normalizers import normalize_snapshot
from icp.rules import assess

NOW = datetime(2026, 10, 6, 22, 0, tzinfo=UTC)
GLOBAL = "62e90394-69f5-4237-9190-012177145e10"
ASSESSOR_APP = "app-icp"
AUTHENTICATOR = [
    {"type": "passwordAuthenticationMethod"},
    {"type": "microsoftAuthenticatorAuthenticationMethod"},
]
PASSWORD_ONLY = [{"type": "passwordAuthenticationMethod"}]


def _user(name, *, enabled=True, guest=False, licensed=True, signed_in=None):
    return {
        "id": f"u-{name}",
        "userPrincipalName": f"{name}@lab.example",
        "displayName": name,
        "accountEnabled": enabled,
        "userType": "Guest" if guest else "Member",
        "createdDateTime": "2026-10-01T10:00:00Z",
        "signInActivity": {"lastSignInDateTime": signed_in} if signed_in else {},
        "assignedLicenses": 1 if licensed else 0,
    }


def _artifacts() -> dict:
    names = [
        "admin",
        "admin-test01",
        "it.contractor",
        "priya",
        "owen",
        "svc-scanner",
        "dana",
        "eli",
        "staff1",
    ]
    users = [_user(n) for n in names] + [
        _user("nina", enabled=False),
        _user("event.temp", enabled=False, licensed=False),
        _user("guest_ext#EXT#", guest=True),
    ]
    methods = {u["id"]: PASSWORD_ONLY for u in users if u["userType"] != "Guest"}
    methods["u-admin"] = [*AUTHENTICATOR, {"type": "fido2AuthenticationMethod"}]
    for n in ("admin-test01", "dana", "eli"):
        methods[f"u-{n}"] = AUTHENTICATOR
    roles = {
        "definitions": [
            {"id": "r-ga", "displayName": "Global Administrator", "templateId": GLOBAL},
            {"id": "r-ex", "displayName": "Exchange Administrator", "templateId": "x"},
            {"id": "r-gr", "displayName": "Global Reader", "templateId": "y"},
        ],
        "assignments": [
            {"principalId": "u-admin", "roleDefinitionId": "r-ga"},
            {"principalId": "u-admin-test01", "roleDefinitionId": "r-ga"},
            {"principalId": "u-it.contractor", "roleDefinitionId": "r-ga"},
            {"principalId": "u-priya", "roleDefinitionId": "r-ex"},
            {"principalId": "u-svc-scanner", "roleDefinitionId": "r-gr"},
        ],
    }
    return {
        "m365.organization": {
            "organization_name": "Identity Posture Lab",
            "domains": [{"name": "lab.example", "is_default": True}],
        },
        "m365.users": users,
        "m365.auth_methods": {"entries": methods},
        "m365.roles": roles,
        "m365.service_principals": [
            {
                "id": "sp-oauth",
                "appId": "app-oauth",
                "displayName": "Posture OAuth Test",
                "appOwnerOrganizationId": "tenant",
            },
            {
                "id": "sp-backup",
                "appId": "app-backup",
                "displayName": "Backup Sync Test",
                "appOwnerOrganizationId": "tenant",
            },
            {
                "id": "sp-icp",
                "appId": ASSESSOR_APP,
                "displayName": "ICP Assessment (read-only)",
                "appOwnerOrganizationId": "tenant",
            },
        ],
        "m365.graph_permissions": {
            "application_grants": [
                {"client_sp_id": "sp-backup", "client_name": "Backup Sync Test", "permission": "Mail.Read"},
                {
                    "client_sp_id": "sp-icp",
                    "client_name": "ICP Assessment (read-only)",
                    "permission": "Sites.Read.All",
                },
            ],
            "delegated_grants": [
                {
                    "clientId": "sp-oauth",
                    "consentType": "Principal",
                    "principalId": "u-nina",
                    "scope": "openid User.Read Mail.Read",
                },
                {
                    "clientId": "sp-oauth",
                    "consentType": "Principal",
                    "principalId": "u-eli",
                    "scope": "openid offline_access User.Read Mail.Read",
                },
                {
                    "clientId": "sp-backup",
                    "consentType": "AllPrincipals",
                    "principalId": None,
                    "scope": "User.Read",
                },
            ],
            "low_impact_classifications": [
                {"permissionName": p} for p in ("Mail.Read", "User.Read", "openid")
            ],
        },
        "m365.applications": [
            {
                "appId": "app-backup",
                "displayName": "Backup Sync Test",
                "secrets": [
                    {"startDateTime": "2026-10-06T00:00:00Z", "endDateTime": "2028-10-05T00:00:00Z"}
                ],
                "certificates": [],
            },
            {
                "appId": ASSESSOR_APP,
                "displayName": "ICP Assessment (read-only)",
                "secrets": [],
                "certificates": [
                    {"startDateTime": "2026-10-06T00:00:00Z", "endDateTime": "2027-04-04T00:00:00Z"}
                ],
            },
        ],
        "m365.policies": {
            "security_defaults_enabled": False,
            "authorization": {
                "permission_grant_policies": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"],
                "users_can_register_apps": True,
                "allow_invites_from": "everyone",
            },
            "conditional_access": [
                {
                    "displayName": "Require multifactor authentication for admins",
                    "state": "enabled",
                    "grant_controls": ["mfa"],
                    "users": {"includeRoles": [GLOBAL]},
                    "applications": {"includeApplications": ["All"]},
                },
                {
                    "displayName": "Require multifactor authentication for all users",
                    "state": "disabled",
                    "grant_controls": ["mfa"],
                    "users": {"includeUsers": ["All"]},
                    "applications": {"includeApplications": ["All"]},
                },
                {
                    "displayName": "Require multifactor authentication for Azure management",
                    "state": "enabled",
                    "grant_controls": ["mfa"],
                    "users": {"includeUsers": ["All"]},
                    "applications": {"includeApplications": ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]},
                },
            ],
        },
        "m365.sharepoint_settings": {"sharingCapability": "externalUserAndGuestSharing"},
        # Microsoft's defaults: nothing trusted, shared channels blocked.
        "m365.cross_tenant_access": {
            "default": {
                "inboundTrust": {
                    "isMfaAccepted": False,
                    "isCompliantDeviceAccepted": False,
                    "isHybridAzureADJoinedDeviceAccepted": False,
                },
                "b2bDirectConnectInbound": {
                    "usersAndGroups": {
                        "accessType": "blocked",
                        "targets": [{"target": "AllUsers", "targetType": "user"}],
                    }
                },
            },
            "partners": [],
        },
        "m365.public_files": [
            {
                "id": "f1",
                "name": "TEST board papers.docx",
                "owner": "dana@lab.example",
                "owner_enabled": True,
            },
            {
                "id": "f2",
                "name": "TEST departed owner file.docx",
                "owner": "nina@lab.example",
                "owner_enabled": False,
            },
        ],
        "m365.audit_readiness": {
            "probe_window_days": 7,
            "streams": {
                "directory_audit": {"available": True, "events_sampled": 50},
                "sign_ins": {"available": True, "events_sampled": 50},
            },
        },
        "m365.assessor": {"client_id": ASSESSOR_APP},
    }


def _run(artifacts=None, **snapshot_fields):
    snapshot = Snapshot(
        snapshot_id="20261006T220000000Z-test",
        tenant_id="m365",
        platform=Platform.MICROSOFT_365,
        collected_at=NOW,
        artifacts=artifacts or _artifacts(),
        **snapshot_fields,
    )
    tenant = normalize_snapshot(snapshot)
    result = assess(tenant, now=NOW)
    by_rule: dict[str, list] = {}
    for f in result.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    return tenant, result, by_rule


def labels(finding) -> set[str]:
    return {e.label.split("@")[0] for e in finding.affected_entities}


@pytest.fixture(scope="module")
def seeded():
    return _run()


# -- the planted problems -------------------------------------------------------------


EXPECTED = {
    "M365-MFA-001": {"it.contractor", "priya", "svc-scanner"},  # admins, password only
    "M365-MFA-002": {"owen", "staff1"},  # staff, password only (owen has no role here)
    "M365-MFA-003": {"admin-test01"},  # admin with Authenticator only; admin has a passkey
    "M365-ADM-001": {"admin", "admin-test01", "it.contractor"},
    "M365-STA-003": {"nina", "event.temp"},
    "M365-SHR-001": {"TEST board papers.docx", "TEST departed owner file.docx"},
    "M365-OAU-002": {"nina"},
}


@pytest.mark.parametrize("rule_id", sorted(EXPECTED))
def test_names_exactly_the_planted_accounts(seeded, rule_id):
    _, _, by_rule = seeded
    [finding] = by_rule[rule_id]
    assert labels(finding) == EXPECTED[rule_id]


def test_guests_never_count_as_staff(seeded):
    tenant, _, by_rule = seeded
    assert [g.label for g in tenant.guests] == ["guest_ext#EXT#@lab.example"]
    assert not any("guest" in label for label in labels(by_rule["M365-MFA-002"][0]))


def test_app_only_mailbox_access_and_the_long_lived_secret(seeded):
    _, _, by_rule = seeded
    [app_only] = by_rule["M365-SVC-001"]
    assert labels(app_only) == {"Backup Sync Test"}
    [secret] = by_rule["M365-SVC-002"]
    assert "730 days, until 5 October 2028" in secret.evidence[0].summary


def test_the_assessment_app_is_never_its_own_finding(seeded):
    """Found live: the tool's own Sites.Read.All flagged the tool itself."""
    _, result, _ = seeded
    assert not any("ICP Assessment" in e.label for f in result.findings for e in f.affected_entities)


def test_staying_signed_in_is_called_out_for_the_person_who_allowed_it(seeded):
    _, _, by_rule = seeded
    [broad] = by_rule["M365-OAU-001"]
    assert labels(broad) == {"eli", "nina"}
    assert "eli@lab.example" in broad.evidence[0].summary and "offline access" in broad.evidence[0].summary


def test_mail_access_classified_low_impact_is_reported(seeded):
    _, _, by_rule = seeded
    assert "Mail.Read" in by_rule["M365-OAU-003"][0].title


@pytest.mark.parametrize("rule_id", ["M365-SHR-002", "M365-SHR-003", "M365-OAU-004"])
def test_permissive_organization_settings_are_reported(seeded, rule_id):
    _, _, by_rule = seeded
    assert rule_id in by_rule


# -- live false results, fixed ---------------------------------------------------------


def test_a_policy_for_one_application_is_not_an_organization_wide_requirement(seeded):
    """Found live: an enabled 'all users' policy scoped to Azure management made
    the organization look protected; the real 'all users' policy was off."""
    _, _, by_rule = seeded
    [finding] = by_rule["M365-MFA-004"]
    assert finding.severity.value == "critical"


def test_an_enabled_all_users_all_apps_policy_does_count():
    artifacts = deepcopy(_artifacts())
    artifacts["m365.policies"]["conditional_access"][1]["state"] = "enabled"
    _, _, by_rule = _run(artifacts)
    assert "M365-MFA-004" not in by_rule


def test_report_only_does_not_count():
    artifacts = deepcopy(_artifacts())
    artifacts["m365.policies"]["conditional_access"][1]["state"] = "enabledForReportingButNotEnforced"
    _, _, by_rule = _run(artifacts)
    assert "M365-MFA-004" in by_rule


def test_the_admin_policy_waiting_for_a_first_sign_in_is_explained(seeded):
    _, _, by_rule = seeded
    summary = by_rule["M365-MFA-001"][0].evidence[0].summary
    assert "Require multifactor authentication for admins" in summary
    assert "whoever signs in next" in summary


def test_no_sign_in_data_makes_age_checks_not_assessed_not_everyone_stale(seeded):
    """Live on day one: Microsoft had recorded no sign-in time for any account."""
    _, result, by_rule = seeded
    for rule_id in ("M365-STA-001", "M365-STA-002", "M365-ADM-002"):
        assert rule_id not in by_rule
        assert "not yet recorded a last sign-in time" in result.unassessable[rule_id]


def test_with_sign_in_data_an_old_account_is_flagged():
    artifacts = deepcopy(_artifacts())
    for u in artifacts["m365.users"]:
        u["createdDateTime"] = "2026-01-01T00:00:00Z"
        u["signInActivity"] = {"lastSignInDateTime": "2026-10-05T09:00:00Z"}
    artifacts["m365.users"][-4]["signInActivity"] = {"lastSignInDateTime": "2026-03-01T09:00:00Z"}  # staff1
    _, _, by_rule = _run(artifacts)
    assert labels(by_rule["M365-STA-002"][0]) == {"staff1"}


# -- platform separation ---------------------------------------------------------------


def test_microsoft_rules_never_run_on_google_and_vice_versa(seeded, result):
    _, m365_result, _ = seeded
    assert all(f.rule_id.startswith(("M365-", "ICP-")) for f in m365_result.findings)
    assert all(f.rule_id.startswith(("GWS-", "ICP-")) for f in result.findings)


# -- one failed source silences only the rules that need it ------------------------------

#: Always "not assessed" in this synthetic tenant: it has no sign-in times.
NO_SIGN_IN_DATA = {"M365-STA-001", "M365-STA-002", "M365-ADM-002"}


def _without(collector: str):
    """The seeded tenant with one collector failed for a missing permission."""
    from icp.models.enums import Assessability
    from icp.models.snapshot import CollectionError

    artifacts = _artifacts()
    del artifacts[collector]
    error = CollectionError(
        collector=collector,
        assessability=Assessability.NOT_ASSESSABLE_PERMISSION,
        message="Access denied (403 accessDenied).",
    )
    _, result, by_rule = _run(artifacts, errors=(error,))
    return result, by_rule


def test_losing_the_sharing_setting_does_not_hide_the_public_files():
    """Found live (13 Oct 2026): consent for SharePointTenantSettings.Read.All
    was revoked. The whole sharing area went "not assessed" and a CRITICAL
    public-file finding, whose data had been collected, disappeared."""
    result, by_rule = _without("m365.sharepoint_settings")

    assert labels(by_rule["M365-SHR-001"][0]) == {"TEST board papers.docx", "TEST departed owner file.docx"}
    assert "M365-SHR-003" in by_rule  # guest invitations: a different source
    assert "M365-SHR-002" not in by_rule
    assert "Access denied" in result.unassessable["M365-SHR-002"]
    assert set(result.unassessable) - NO_SIGN_IN_DATA == {"M365-SHR-002"}


def test_losing_the_file_listing_hides_only_the_file_check():
    result, by_rule = _without("m365.public_files")
    assert set(result.unassessable) - NO_SIGN_IN_DATA == {"M365-SHR-001"}
    assert {"M365-SHR-002", "M365-SHR-003"} <= set(by_rule)


def test_unreadable_roles_never_look_like_no_administrators():
    """The opposite error: with no roles, every admin check would find nobody
    and report a clean result."""
    result, by_rule = _without("m365.roles")
    assert set(result.unassessable) - NO_SIGN_IN_DATA == {"M365-MFA-001", "M365-MFA-003", "M365-ADM-001"}
    assert "M365-ADM-002" in result.unassessable
    assert not {"M365-MFA-001", "M365-MFA-003", "M365-ADM-001"} & set(by_rule)
    assert "M365-MFA-002" in by_rule  # staff coverage still measured


def test_unreadable_policies_do_not_claim_nothing_is_enforced():
    """Without the policies, 'nothing requires a second step' would be a guess."""
    result, by_rule = _without("m365.policies")
    assert {"M365-MFA-004", "M365-SHR-003", "M365-OAU-003", "M365-OAU-004"} <= set(result.unassessable)
    assert "M365-MFA-004" not in by_rule
    assert "M365-SHR-002" in by_rule  # the sharing setting comes from SharePoint, still read


def test_every_microsoft_rule_names_the_sources_it_needs():
    from icp.rules import all_rules

    rules = [r for r in all_rules() if Platform.MICROSOFT_365 in r.platforms]
    assert len(rules) == 21
    assert [r.rule_id for r in rules if not r.requires_collectors] == []


def test_access_on_a_blocked_account_is_reported_as_dormant_not_as_live(seeded):
    """First written as 'can keep reading their mail' (High). Microsoft refuses
    to renew an application's sign-in for a disabled account, so the access
    cannot be used while blocked; the risk is its silent return on re-enable."""
    _, _, by_rule = seeded
    [finding] = by_rule["M365-OAU-002"]
    assert finding.severity.value == "medium"
    summary = finding.evidence[0].summary
    assert "cannot use it while the account stays blocked" in summary
    assert "re-enabled" in summary
    assert "can keep reading" not in summary


def test_the_fix_for_blocked_account_access_is_one_a_client_can_follow(library):
    """Found live: neither the Entra portal nor the user's own My Apps page can
    remove one person's consent to an in-house application."""
    entry = library.entries["m365.apps.revoke_departed"]
    steps = " ".join(entry.steps)
    assert "Delete user" in steps
    assert "has no button" in steps
    assert "Remove-MgOauth2PermissionGrant" in steps
    assert "revoke the access granted by the blocked account" not in steps
    assert "can keep reading" not in entry.impact


# -- Found by the review of the first combined report (13 Oct 2026) ---------------------


def test_the_admin_policy_is_only_claimed_for_a_role_it_covers(seeded):
    """The report said the admin policy "will ask for a second step" of a Global
    Reader, a role that policy does not include."""
    _, _, by_rule = seeded
    by_account = {e.summary.split(" holds ")[0]: e.summary for e in by_rule["M365-MFA-001"][0].evidence}
    assert "will ask for a second step" in by_account["it.contractor@lab.example"]
    reader = by_account["svc-scanner@lab.example"]
    assert "will ask for a second step" not in reader
    assert "does not cover this role" in reader


def test_an_admin_policy_for_one_application_is_not_claimed():
    artifacts = deepcopy(_artifacts())
    artifacts["m365.policies"]["conditional_access"][0]["applications"] = {
        "includeApplications": ["one-app"]
    }
    _, _, by_rule = _run(artifacts)
    assert all("will ask for a second step" not in e.summary for e in by_rule["M365-MFA-001"][0].evidence)


def test_coverage_counts_administrators_without_a_second_step(seeded):
    """It read 42.9% live where the true figure was 28.6%: the three
    administrators with no second step were left out of the uncovered count."""
    tenant, _, by_rule = seeded
    [finding] = by_rule["M365-MFA-002"]
    active = [u for u in tenant.active_users if u.mfa_method_known]
    covered = sum(1 for u in active if u.mfa_enrolled)
    assert any(u.is_privileged and not u.mfa_enrolled for u in active), "fixture must include the case"
    assert (
        f"({covered} of {len(active)} active accounts covered, {round(100 * covered / len(active), 1)}%)"
        in finding.title
    )
    assert finding.evidence[0].observed_values["coverage_pct"] == round(100 * covered / len(active), 1)
    assert "administrator accounts reported separately" in finding.evidence[0].summary


def test_offline_access_is_not_described_as_unconditional(seeded):
    _, _, by_rule = seeded
    summary = by_rule["M365-OAU-001"][0].evidence[0].summary
    assert "at any time" not in summary
    assert "for as long as Microsoft keeps renewing that access, no sign-in policy blocks it" in summary


# -- Found by the second review of the combined report (13 Oct 2026) --------------------


def test_what_an_application_reads_comes_from_its_permission_names(seeded):
    """Mail.Read was reported as "mail or files"; it does not reach OneDrive."""
    from icp.rules.microsoft import readable_kinds

    assert readable_kinds(["Mail.Read"]) == "mail"
    assert readable_kinds(["Mail.Read", "Files.Read.All", "Sites.Read.All"]) == "mail and files"
    assert readable_kinds(["Directory.ReadWrite.All"]) == "data"
    assert readable_kinds(["Directory.ReadWrite.All", "Mail.Read"]) == "mail and other data"
    _, _, by_rule = seeded
    [app_only] = by_rule["M365-SVC-001"]
    assert (
        app_only.title
        == "'Backup Sync Test' holds organization-wide permission to read mail (mailbox limits not checked)"
    )
    assert "cannot see whether an Exchange access policy" in app_only.evidence[0].summary
    assert by_rule["M365-OAU-001"][0].title.startswith("'Posture OAuth Test' can read the mail of ")


def test_the_org_wide_finding_names_each_policy_and_its_state():
    """ "1 policy is present but not switched on" read as contradicting the
    enabled administrator policy reported elsewhere."""
    artifacts = deepcopy(_artifacts())
    artifacts["m365.policies"]["conditional_access"][1]["state"] = "enabledForReportingButNotEnforced"
    _, _, by_rule = _run(artifacts)
    summary = by_rule["M365-MFA-004"][0].evidence[0].summary
    assert "'Require multifactor authentication for all users' (report-only)" in summary
    assert "'Require multifactor authentication for admins' is switched on, but applies to" in summary
    assert "report-only or off" not in summary


def test_the_consent_finding_says_what_the_low_impact_permission_reads(seeded):
    _, _, by_rule = seeded
    summary = by_rule["M365-OAU-003"][0].evidence[0].summary
    assert "read their mail without an administrator" in summary
    assert "mail or files" not in summary


def test_the_admin_fix_covers_roles_the_template_leaves_out():
    """The fix said only "use the template", which does not include Global Reader."""
    from icp.reporting.remediation import RemediationLibrary

    entry = RemediationLibrary.load_default().entries["m365.mfa.enforce_admins"]
    steps = " ".join(entry.steps)
    assert "does not cover this role" in steps and "Directory roles" in steps


# -- Access settings for outside organizations (cross-tenant access) --------------------


def test_microsofts_default_outside_access_settings_raise_nothing(seeded):
    _, result, by_rule = seeded
    assert "M365-SHR-004" not in by_rule and "M365-SHR-005" not in by_rule
    assert not {"M365-SHR-004", "M365-SHR-005"} & set(result.unassessable)


def test_accepting_every_organizations_sign_in_checks_is_flagged():
    artifacts = deepcopy(_artifacts())
    artifacts["m365.cross_tenant_access"]["default"]["inboundTrust"]["isMfaAccepted"] = True
    _, _, by_rule = _run(artifacts)
    [finding] = by_rule["M365-SHR-004"]
    assert finding.severity.value == "low"
    assert "second sign-in step done by any outside organization" in finding.title
    assert "M365-SHR-005" not in by_rule


def test_shared_channels_open_to_every_organization_are_flagged():
    artifacts = deepcopy(_artifacts())
    artifacts["m365.cross_tenant_access"]["default"]["b2bDirectConnectInbound"]["usersAndGroups"][
        "accessType"
    ] = "allowed"
    _, _, by_rule = _run(artifacts)
    [finding] = by_rule["M365-SHR-005"]
    assert finding.severity.value == "medium"
    assert "do not appear in your user list" in finding.evidence[0].summary


def test_a_snapshot_taken_before_this_check_says_not_assessed_not_clean():
    """The saved snapshots predate the collector: a missing reading is not a pass."""
    artifacts = deepcopy(_artifacts())
    del artifacts["m365.cross_tenant_access"]
    _, result, by_rule = _run(artifacts)
    assert "M365-SHR-004" not in by_rule and "M365-SHR-005" not in by_rule
    assert {"M365-SHR-004", "M365-SHR-005"} <= set(result.unassessable)
    assert "M365-SHR-001" in by_rule  # the rest of the sharing family still runs
