"""Report rendering.

The report is the product, so these tests care about what a client would
actually notice: missing content, unescaped input, and silently omitted checks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from icp.reporting.executive_summary import build as build_summary
from icp.reporting.remediation import MissingRemediationContent, RemediationLibrary
from icp.reporting.renderer import ReportRenderer
from icp.rules import all_rules


@pytest.fixture(scope="module")
def renderer() -> ReportRenderer:
    return ReportRenderer()


@pytest.fixture(scope="module")
def html(renderer, tenant, result) -> str:
    context = renderer.build_context(
        tenant, result, client_name="Riverside Community Trust", assessor="Test Assessor"
    )
    return renderer.env.get_template("report.html").render(**context)


# -- content completeness ------------------------------------------------------


def test_every_rule_has_remediation_content(library: RemediationLibrary):
    """A finding with an empty remediation box is worse than no report.

    This is the check that stops a new rule from shipping half-finished.
    """
    missing = [rule.rule_id for rule in all_rules() if rule.remediation_key not in library.entries]
    assert missing == [], f"rules without remediation content: {missing}"


def test_remediation_entries_meet_the_editorial_standard(library: RemediationLibrary):
    """Impact in plain language, steps concrete enough to follow."""
    for key, entry in library.entries.items():
        assert entry.impact, f"{key} has no impact statement"
        assert len(entry.impact) > 60, f"{key} impact is too terse to be useful"
        assert entry.steps, f"{key} has no steps"
        assert len(entry.steps) >= 2, f"{key} needs more than one step"
        assert "consider reviewing" not in entry.impact.lower(), f"{key} is vague filler"


def test_renderer_refuses_to_render_with_missing_content(tenant, result):
    """Fail loudly rather than shipping a gap the client will find."""
    empty = RemediationLibrary(entries={}, version="test")
    with pytest.raises(KeyError, match="remediation content missing"):
        ReportRenderer(library=empty).build_context(tenant, result, client_name="X", assessor="Y")


def test_missing_key_lookup_explains_itself(library: RemediationLibrary):
    with pytest.raises(MissingRemediationContent, match=r"config/remediation\.yaml"):
        library.get("does.not.exist")


# -- security of the rendered artifact ----------------------------------------


@pytest.mark.security
def test_client_controlled_strings_are_escaped(renderer, tenant, result):
    """Application and file names come from the client's tenant.

    The HTML report gets forwarded by email and opened in a browser, so an
    unescaped app name would be a stored-XSS vector in a document we hand to a
    security client. Autoescaping is on; this proves it.
    """
    hostile = "<script>alert('xss')</script>"
    poisoned = [
        f.model_copy(update={"title": hostile}) if i == 0 else f for i, f in enumerate(result.findings)
    ]
    tampered = type(result)(
        findings=poisoned,
        rules_run=result.rules_run,
        rules_failed=result.rules_failed,
        unassessable=result.unassessable,
    )
    context = renderer.build_context(tenant, tampered, client_name="X", assessor="Y")
    rendered = renderer.env.get_template("report.html").render(**context)

    assert "<script>alert" not in rendered
    assert "&lt;script&gt;" in rendered


@pytest.mark.security
def test_template_fails_on_an_undefined_variable(renderer):
    """StrictUndefined: a typo in a template must break the build, not the report."""
    from jinja2 import UndefinedError

    template = renderer.env.from_string("{{ nonexistent_variable }}")
    with pytest.raises(UndefinedError):
        template.render()


# -- what the client reads -----------------------------------------------------


def test_report_states_what_was_not_examined(html: str):
    assert "What we did not examine" in html
    assert "contents of any email" in html


def test_report_states_the_read_only_method(html: str):
    assert "read-only" in html.lower()
    assert "nothing in your environment was changed" in html.lower()


def test_report_disclaims_certification(html: str):
    """Selling an 'audit' without being an auditor is a real liability."""
    assert "not an audit" in html.lower()
    assert "not an attestation" in html.lower()


def test_report_lists_every_connected_application(html: str, tenant):
    """Unflagged apps included: the sign-in-only Payroll Portal has no finding
    but must still appear, or the client cannot spot the app nobody knows."""
    assert "Connected applications" in html
    for app in tenant.applications:
        assert app.name in html
    assert "Payroll Portal" in html
    assert "not registered with Google" in html
    assert "Google developer tool" in html
    # Honest about what Google does not expose.
    assert "does not publish whether an application has passed its verification" in html


def test_action_plan_lists_distinct_actions(renderer, tenant, result):
    """Ten entries about the same fix would push real work off the page."""
    context = renderer.build_context(tenant, result, client_name="X", assessor="Y")
    plan = context["action_plan"]
    keys = [item["finding"].remediation_key for item in plan]
    assert len(keys) == len(set(keys))
    assert len(plan) <= 10


def test_action_plan_is_ordered_by_severity_then_value_per_hour(renderer, tenant, result):
    context = renderer.build_context(tenant, result, client_name="X", assessor="Y")
    keys = [(item["finding"].severity.rank, item["risk_per_hour"]) for item in context["action_plan"]]
    assert keys == sorted(keys, reverse=True)


def test_every_finding_carries_traceable_evidence(result):
    for finding in result.findings:
        assert finding.evidence, f"{finding.rule_id} has no evidence"
        for item in finding.evidence:
            assert item.collector
            assert item.pointer
            assert item.summary


def test_executive_summary_avoids_jargon(tenant, result):
    """Written for a director who will read one page and nothing else."""
    summary = build_summary(tenant, result.findings)
    text = summary.opening + " ".join(r.paragraph for r in summary.headline_risks)
    for jargon in ("OAuth", "2SV", "API", "MFA", "scope tier", "blast radius"):
        assert jargon not in text, f"executive summary uses {jargon!r}"


def test_executive_summary_picks_three_distinct_problems(tenant, result):
    summary = build_summary(tenant, result.findings)
    assert len(summary.headline_risks) == 3
    headings = [r.heading for r in summary.headline_risks]
    assert len(set(headings)) == 3


def test_headline_risks_never_put_a_milder_issue_above_a_worse_one(tenant, result):
    """The board reads these as "most dangerous first"."""
    from icp.models.enums import Severity

    summary = build_summary(tenant, result.findings)
    by_id = {f.finding_id: f for f in result.findings}
    ranks = [by_id[r.finding_ids[0]].severity.rank for r in summary.headline_risks]
    assert ranks == sorted(ranks, reverse=True)
    assert all(r >= Severity.MEDIUM.rank for r in ranks[:1])


def test_coverage_notes_are_rendered_not_omitted(renderer, tenant, result):
    """A check that could not run must never look like a check that passed."""
    context = renderer.build_context(tenant, result, client_name="X", assessor="Y")
    notes = context["coverage_notes"]
    if notes:
        rendered = renderer.env.get_template("report.html").render(**context)
        assert "not a pass" in rendered.lower()


def test_html_and_pdf_are_written(renderer, tenant, result, tmp_path: Path):
    rendered = renderer.render(
        tenant, result, tmp_path, client_name="Riverside Community Trust", assessor="Test"
    )
    assert rendered.html_path.exists()
    assert rendered.html_path.stat().st_size > 10_000
    if rendered.pdf_path is None:
        pytest.skip(f"WeasyPrint unavailable: {rendered.pdf_error}")
    assert rendered.pdf_path.stat().st_size > 10_000


def test_one_entry_per_application_without_losing_any_result(renderer, tenant, result):
    """Against a real tenant, one admin's four apps became fourteen findings.

    Grouping must shorten the client-facing pages without dropping anything:
    every individual result still reaches the appendix, and a grouped entry is
    never shown milder than a reason listed beneath it.
    """
    from icp.models.enums import Severity
    from icp.reporting.consolidation import PER_APPLICATION_RULES, consolidate

    actionable = [f for f in result.findings if f.severity != Severity.INFO]
    entries = consolidate(actionable)

    shown = [e.finding for e in entries] + [r for e in entries for r in e.related]
    assert sorted(f.finding_id for f in shown) == sorted(f.finding_id for f in actionable)

    for entry in entries:
        for related in entry.related:
            assert related.rule_id in PER_APPLICATION_RULES
            assert related.severity.rank <= entry.finding.severity.rank

    context = renderer.build_context(tenant, result, client_name="X", assessor="Y")
    appendix_ids = {c["finding"].finding_id for cs in context["appendix_by_family"].values() for c in cs}
    assert appendix_ids == {f.finding_id for f in actionable}


def test_a_clean_area_is_reported_as_checked(renderer, tenant, result):
    """A family with no findings must read as "looked, fine", not be invisible."""
    from icp.models.enums import CheckFamily

    clean = type(result)(
        findings=[f for f in result.findings if f.check_family != CheckFamily.LOGGING_READINESS],
        rules_run=result.rules_run,
        rules_failed=result.rules_failed,
        unassessable=result.unassessable,
    )
    context = renderer.build_context(tenant, clean, client_name="X", assessor="Y")
    titles = [a["title"] for a in context["passed_areas"]]
    assert "Audit and logging readiness" in titles

    rendered = renderer.env.get_template("report.html").render(**context)
    assert "Areas checked with no issues found" in rendered


def test_severity_is_never_carried_by_colour_alone(html: str):
    """Board packets get printed in greyscale."""
    for label in ("Critical", "High", "Medium", "Low"):
        assert label in html
