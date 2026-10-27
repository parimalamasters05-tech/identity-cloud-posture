"""One report for a client on several platforms.

The brief's week-5 done-when test: "one command against a mixed-platform
client produces one coherent report, and Workspace results are byte-comparable
to the week-4 baseline." The second half is `tests/test_google_baseline.py`;
this is the first, plus the guarantee that a single-platform report is the
same templates with one part.
"""

from __future__ import annotations

import re

import pytest
import yaml
from tests.conftest import REPO_ROOT
from tests.reporting.test_plain_language import EVERYWHERE, _violations
from tests.rules.test_m365_rules import _run

from icp.models.enums import Platform, Severity
from icp.reporting.renderer import ReportRenderer

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(r"<style.*?</style>", " ", html, flags=re.S)))


@pytest.fixture(scope="module")
def combined(tenant, result):
    from icp.collectors.microsoft import PERMISSIONS_USED

    m365_tenant, m365_result, _ = _run(scopes_used=PERMISSIONS_USED)
    renderer = ReportRenderer()
    context = renderer.build_combined_context(
        [(tenant, result), (m365_tenant, m365_result)], client_name="Lab", assessor="T"
    )
    html = renderer.env.get_template("report.html").render(**context)
    return context, _text(html).replace("&#39;", "'").replace("&middot;", "·"), (result, m365_result)


def test_one_report_names_both_platforms_on_the_cover(combined):
    context, text, _ = combined
    assert context["combined"] is True and len(context["parts"]) == 2
    assert "Google Workspace and Microsoft 365 · point-in-time review" in text
    assert "Google Workspace: " in text and "Microsoft 365: " in text


def test_every_finding_from_both_platforms_is_in_the_one_report(combined):
    context, _, (google, m365) = combined
    shown = {e["finding"].finding_id for entries in context["appendix_by_family"].values() for e in entries}
    expected = {f.finding_id for r in (google, m365) for f in r.findings if f.severity != Severity.INFO}
    assert shown == expected


def test_one_action_plan_ranks_both_platforms_most_serious_first(combined):
    context, _, _ = combined
    plan = context["action_plan"]
    assert {item["finding"].platform for item in plan} == {
        Platform.GOOGLE_WORKSPACE,
        Platform.MICROSOFT_365,
    }
    bands = [SEVERITY_ORDER.index(item["finding"].severity) for item in plan]
    assert bands == sorted(bands), "a less severe item is ranked above a more severe one"


def test_each_finding_and_action_says_which_platform_it_is_in(combined):
    context, text, _ = combined
    for item in context["action_plan"]:
        name = "Microsoft 365" if item["finding"].platform == Platform.MICROSOFT_365 else "Google Workspace"
        assert f"{name}: {item['finding'].title}" in text
    for risk in context["summary"].headline_risks:
        assert risk.heading.endswith(("(Google Workspace)", "(Microsoft 365)"))


def test_the_summary_counts_accounts_per_platform(combined, tenant):
    context, _, _ = combined
    opening = context["summary"].opening
    assert "your Google Workspace and Microsoft 365 environments" in opening
    assert f"{len(tenant.active_users)} in Google Workspace" in opening
    assert "in Microsoft 365" in opening


def test_access_method_and_read_only_proof_are_given_per_platform(combined):
    _, text, _ = combined
    assert "Google Workspace: Scopes used" in text and "Microsoft 365: Permissions used" in text
    assert (
        "Google Workspace: Read-only verification" in text
        and "Microsoft 365: Read-only verification" in text
    )
    # each platform's own caveat, and its own log to check
    assert "Not a read-only scope" in text and "Read-only, but could read file contents" in text
    assert "your own admin audit log" in text and "your Microsoft Entra audit log" in text
    # the scoring explanation is not repeated
    assert text.count("How findings are scored") == 1


def test_connected_applications_are_listed_per_platform(combined):
    _, text, _ = combined
    assert "Connected applications: Google Workspace" in text
    assert "Connected applications: Microsoft 365" in text


def test_clean_areas_and_cover_method_are_not_mixed_up(combined):
    context, _, _ = combined
    assert all(
        a["title"].startswith(("Google Workspace: ", "Microsoft 365: ")) for a in context["passed_areas"]
    )
    method = context["scope_statement"]["method"]
    assert "could in principle remove connections" in method and "could open file contents" in method


def test_the_combined_text_is_plain(combined):
    context, _, _ = combined
    problems = []
    for item in context["action_plan"]:
        for evidence in item["finding"].evidence:
            problems += _violations(evidence.summary, EVERYWHERE)
    for risk in context["summary"].headline_risks:
        problems += _violations(risk.paragraph, EVERYWHERE)
    assert problems == []


def test_a_single_platform_report_is_one_part_and_carries_no_platform_tags(tenant, result):
    renderer = ReportRenderer()
    context = renderer.build_context(tenant, result, client_name="Lab", assessor="T")
    assert context["combined"] is False and len(context["parts"]) == 1
    text = _text(renderer.env.get_template("report.html").render(**context))
    assert "Google Workspace: " not in text  # tags appear only when there is something to tell apart
    assert "Microsoft" not in text


def test_a_combined_report_needs_two_platforms(tenant, result):
    with pytest.raises(ValueError, match="at least two"):
        ReportRenderer().build_combined_context([(tenant, result)], client_name="Lab", assessor="T")


def test_every_fix_has_a_time_estimate_on_the_shared_scale():
    """Found reading the first combined report: closing one public file read
    "20 minutes" for Google and "3 hours" for Microsoft, because no Microsoft
    fix had an estimate and each fell back to its rule's rough default."""
    from icp.rules import all_rules

    configured = yaml.safe_load((REPO_ROOT / "config" / "risk_matrix.yaml").read_text("utf-8"))[
        "effort_hours"
    ]
    missing = sorted({r.remediation_key for r in all_rules()} - set(configured))
    assert missing == []


def test_the_same_work_takes_the_same_time_on_both_platforms(combined):
    context, _, _ = combined
    public = {
        e["finding"].platform: e["finding"]
        for entries in context["appendix_by_family"].values()
        for e in entries
        if e["finding"].rule_id in ("GWS-SHR-001", "M365-SHR-001")
    }
    google, m365 = public[Platform.GOOGLE_WORKSPACE], public[Platform.MICROSOFT_365]
    per_item = lambda f: (f.effort_hours - 0.25) / f.entity_count  # noqa: E731
    assert per_item(google) == pytest.approx(per_item(m365))


def test_each_platforms_access_statement_is_its_own_paragraph(combined, tenant, result):
    """They shared one paragraph and ran together: "explained below.Microsoft 365."."""
    context, _, _ = combined
    html = ReportRenderer().env.get_template("report.html").render(**context)
    assert html.count("<p><strong>Google Workspace.</strong>") == 1
    assert html.count("<p><strong>Microsoft 365.</strong>") == 1
    section = html.split("How the assessment ran")[1].split("The tool performs")[0]
    assert section.count("<p>") == section.count("</p>") + 1  # the shared closing paragraph opens last


def test_the_summary_says_what_the_application_reads(combined):
    context, _, _ = combined
    for risk in context["summary"].headline_risks:
        if "Backup Sync Test" in risk.paragraph:
            assert "mail or files" not in risk.paragraph


def test_a_report_with_aws_names_it_as_an_account_read_by_prowler(tenant, result):
    """AWS has no staff directory and is read by Prowler: the cover and
    summary must not describe it in Workspace and Microsoft terms."""
    from tests.rules.test_aws_rules import _run as run_aws

    _, aws_tenant, aws_result, _ = run_aws()
    renderer = ReportRenderer()
    context = renderer.build_combined_context(
        [(tenant, result), (aws_tenant, aws_result)], client_name="Lab", assessor="T"
    )
    examined = context["scope_statement"]["examined"]
    assert examined[0] == "Your staff directories in Google Workspace: accounts, guests and groups"
    assert any(line.startswith("In AWS:") for line in examined)
    assert "Prowler" in context["scope_statement"]["method"]
    opening = context["summary"].opening
    staff = len(tenant.active_users)
    assert f"covering {staff} active staff accounts ({staff} in Google Workspace)" in opening
    assert 'your AWS account 111122223333 ("lab")' in opening
    html = renderer.env.get_template("report.html").render(**context)
    text = _text(html)
    assert "made no requests to AWS: it read the results file Prowler wrote" in text
    assert "Policies the assessment role was set up with" in text and "SecurityAudit" in text


# -- Review of 14 Oct (second three-platform report) ---------------------------------


def test_urgency_matches_the_overall_position(combined):
    context, _, _ = combined
    opening = context["summary"].opening
    assert "this week" not in opening
    if context["summary"].rating == "Action required":
        assert "attention now" in opening


def test_a_test_environment_is_said_on_the_cover_and_in_the_summary(tenant, result):
    plain = ReportRenderer().build_context(tenant, result, client_name="Lab", assessor="T")
    for flag, expected in ((False, 0), (True, 2)):
        renderer = ReportRenderer(test_environment=flag)
        text = _text(renderer.env.get_template("report.html").render(**plain))
        assert text.count("Test environment") == expected


def test_the_aws_read_only_claim_rests_on_cloudtrail_not_policy_names():
    from icp.reporting.platform_text import AWS

    assert "did not read back" in AWS.verification
    assert "every event for it is a read" in AWS.verification
    assert "set up with" in AWS.permissions_heading


def test_combined_cover_says_sharepoint_sites_were_not_checked_for_public_links():
    from icp.models.enums import Platform
    from icp.reporting.platform_text import combined

    with_m365 = combined([Platform.GOOGLE_WORKSPACE, Platform.MICROSOFT_365])
    assert any("SharePoint sites" in line for line in with_m365.not_examined)
    without = combined([Platform.GOOGLE_WORKSPACE, Platform.AWS])
    assert not any("SharePoint" in line for line in without.not_examined)
