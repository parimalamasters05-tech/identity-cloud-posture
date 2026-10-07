"""The Microsoft 365 report speaks Microsoft, and the Google report stays Google.

Found rendering the first live Microsoft report (6 Oct 2026):
  * the methodology called all nine read-only Graph permissions "not a
    read-only scope", because the Google rule (".readonly" suffix) judged them;
  * cover, summary, action plan and inventory said "Google";
  * the "checked with no issues" areas listed both platforms' checks, which
    put Microsoft check names into the Google report too.
"""

from __future__ import annotations

import re

import pytest
from tests.reporting.test_plain_language import EVERYWHERE, _violations
from tests.rules.test_m365_rules import _run

from icp.models.enums import Platform
from icp.reporting.renderer import ReportRenderer


@pytest.fixture(scope="module")
def m365():
    from icp.collectors.microsoft import PERMISSIONS_USED

    # The permission set a live run records, so the access claims are judged on it.
    tenant, result, _ = _run(scopes_used=PERMISSIONS_USED)
    renderer = ReportRenderer()
    context = renderer.build_context(tenant, result, client_name="Lab", assessor="T")
    html = renderer.env.get_template("report.html").render(**context)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    return context, text


def test_no_google_wording_anywhere(m365):
    _, text = m365
    assert not re.search(r"(?i)google|workspace|admin console", text)


def test_read_only_claims_are_true_for_graph_permissions(m365):
    context, text = m365
    assert context["write_capable_scopes"] == []
    assert "All are read-only permissions" in text
    assert "Not a read-only" not in text


def test_the_file_content_caveat_is_stated_with_its_safeguard(m365):
    context, text = m365
    assert [p for p, _ in context["content_capable_scopes"]] == ["Sites.Read.All"]
    assert "could in principle open file contents" in context["scope_statement"]["method"]
    assert "Read-only, but could read file contents" in text
    assert "refuses, before sending, any request for a file's contents" in text.replace("&#39;", "'")


def test_live_permission_set_gets_the_content_caveat():
    """With the nine permissions a real run records."""
    from icp.collectors.microsoft import PERMISSIONS_USED
    from icp.reporting.platform_text import MICROSOFT

    assert MICROSOFT.write_capable(PERMISSIONS_USED) == []
    assert [p for p, _ in MICROSOFT.content_capable(PERMISSIONS_USED)] == ["Sites.Read.All"]


def test_write_permissions_would_be_named():
    from icp.reporting.platform_text import MICROSOFT

    flagged = [
        p
        for p, _ in MICROSOFT.write_capable(
            ("User.Read.All", "Mail.ReadWrite", "Mail.Send", "Directory.Read.All")
        )
    ]
    assert flagged == ["Mail.ReadWrite", "Mail.Send"]


def test_the_cover_and_method_name_microsoft(m365):
    context, text = m365
    assert "Microsoft 365 · point-in-time review" in text.replace("&middot;", "·")
    assert context["scope_statement"]["method"].startswith(
        "Read-only. Settings were read through Microsoft Graph"
    )


def test_inventory_lists_app_only_access_and_the_assessment_app(m365):
    context, _ = m365
    kinds = {a.name: a.first_party_kind for a in context["applications"]}
    assert kinds["Backup Sync Test"] == "app_only"
    assert kinds["ICP Assessment (read-only)"] == "assessor"


def test_evidence_and_action_plan_are_plain(m365):
    context, _ = m365
    problems = []
    for entry in context["action_plan"]:
        for evidence in entry["finding"].evidence:
            problems += _violations(evidence.summary, EVERYWHERE)
    assert problems == []


def test_clean_areas_list_only_this_platforms_checks(m365, tenant, result):
    m365_context, _ = m365
    for area in m365_context["passed_areas"]:
        assert not any("super-administrator" in c.lower() for c in area["checks"])
    google = ReportRenderer().build_context(tenant, result, client_name="X", assessor="Y")
    assert tenant.platform == Platform.GOOGLE_WORKSPACE
    for area in google["passed_areas"]:
        assert not any(
            word in c.lower() for c in area["checks"] for word in ("global administrator", "activity logs")
        )


def test_an_app_with_both_kinds_of_access_shows_its_highest(m365):
    """Found live: Backup Sync Test also held an admin-approved User.Read, and
    the inventory listed it as 'Sign-in only', hiding app-only Mail.Read."""
    context, _ = m365
    [app] = [a for a in context["applications"] if a.name == "Backup Sync Test"]
    assert "Mail.Read" in app.scopes
    assert app.max_tier.value == "full_data_read"
