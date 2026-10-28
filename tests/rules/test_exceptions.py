"""Reviewed exceptions: business context, recorded and visible (review, 27 Oct 2026)."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from tests.rules.test_m365_rules import _run

from icp.models.finding import AcceptedException
from icp.reporting.renderer import ReportRenderer
from icp.rules import assess
from icp.rules.exceptions import ExceptionsError, apply, load

EXAMPLE = Path(__file__).resolve().parents[2] / "docs" / "exceptions.example.yaml"


def _x(
    rule: str, entity: str, *, approved: str = "2026-10-01", expires: str = "2027-01-01"
) -> AcceptedException:
    return AcceptedException(
        rule_id=rule,
        entity=entity,
        owner="Jane Example",
        rationale="Legitimate here.",
        compensating_control="Monitored.",
        approved_on=date.fromisoformat(approved),
        expires=date.fromisoformat(expires),
    )


def _assessed(exceptions):
    tenant, _, _ = _run()
    return tenant, assess(tenant, now=tenant.snapshot.collected_at, exceptions=exceptions)


def _finding(result, rule_id):
    return next(f for f in result.findings if f.rule_id == rule_id)


def test_the_documented_example_loads():
    loaded = load(EXAMPLE)
    assert [x.rule_id for x in loaded] == ["M365-ADM-002", "M365-ADM-001"]


@pytest.mark.parametrize(
    ("entry", "complaint"),
    [
        ({"rule": "R", "entity": "e"}, "missing owner"),
        (
            {
                "rule": "R",
                "entity": "e",
                "owner": "o",
                "rationale": "r",
                "compensating_control": "c",
                "approved_on": "2026-10-01",
                "expires": "soon",
            },
            "expires must be a date",
        ),
        (
            {
                "rule": "R",
                "entity": "e",
                "owner": "o",
                "rationale": "r",
                "compensating_control": "c",
                "approved_on": "2026-10-01",
                "expires": "2026-09-01",
            },
            "must be after approved_on",
        ),
    ],
)
def test_an_incomplete_or_inconsistent_exception_is_refused(tmp_path, entry, complaint):
    import yaml

    path = tmp_path / "exceptions.yaml"
    path.write_text(yaml.safe_dump({"exceptions": [entry]}), encoding="utf-8")
    with pytest.raises(ExceptionsError, match=complaint):
        load(path)


def test_a_wholly_excepted_finding_leaves_the_action_plan_but_stays_visible():
    tenant, before = _assessed(None)
    admins = _finding(before, "M365-ADM-001")
    _, result = _assessed([_x("M365-ADM-001", "*")])
    excepted = _finding(result, "M365-ADM-001")

    assert excepted.fully_excepted
    assert excepted.affected_entities == admins.affected_entities  # observation unchanged
    assert excepted.risk_score == admins.risk_score

    renderer = ReportRenderer()
    context = renderer.build_context(tenant, result, client_name="X", assessor="Y")
    assert all(item["finding"].rule_id != "M365-ADM-001" for item in context["action_plan"])
    assert [row["finding"].rule_id for row in context["exceptions"]["accepted"]] == ["M365-ADM-001"]
    html = re.sub(r"\s+", " ", renderer.env.get_template("report.html").render(**context))
    assert "Accepted exceptions" in html and "The finding as a whole" in html and "Jane Example" in html
    appendix = html.split("Appendix", 1)[-1]
    assert admins.finding_id in appendix  # its evidence is kept


def test_a_partly_excepted_finding_stays_with_the_excepted_item_named():
    _, before = _assessed(None)
    admins = _finding(before, "M365-ADM-001")
    one = admins.affected_entities[0]
    tenant, result = _assessed([_x("M365-ADM-001", one.id)])
    finding = _finding(result, "M365-ADM-001")
    assert not finding.fully_excepted and finding.excepted_ids == {one.id}

    renderer = ReportRenderer()
    context = renderer.build_context(tenant, result, client_name="X", assessor="Y")
    assert any(item["finding"].rule_id == "M365-ADM-001" for item in context["action_plan"])
    html = re.sub(r"\s+", " ", renderer.env.get_template("report.html").render(**context))
    assert f"{one.label}</strong>: accepted by Jane Example" in html


def test_expired_not_yet_valid_and_unmatched_exceptions_are_listed_not_applied():
    now = datetime(2026, 10, 6, tzinfo=UTC)
    expired = _x("M365-ADM-001", "*", approved="2026-01-01", expires="2026-06-30")
    later = _x("M365-ADM-001", "*", approved="2026-12-01", expires="2027-06-30")
    nothing = _x("M365-ADM-001", "no-such-account")
    _, before = _assessed(None)
    findings, report = apply(before.findings, [expired, later, nothing], now)
    assert not any(f.exceptions for f in findings)
    assert report.expired == [expired] and report.not_yet_valid == [later] and report.unused == [nothing]


def test_the_expiry_date_is_the_last_day_an_exception_applies():
    _, before = _assessed(None)
    on_the_day = datetime(2027, 1, 1, 18, 0, tzinfo=UTC)
    _, report = apply(before.findings, [_x("M365-ADM-001", "*")], on_the_day)
    assert report.applied and not report.expired


def test_coverage_notes_are_never_excepted():
    _, before = _assessed(None)
    notes = [f for f in before.findings if f.rule_id.startswith("ICP-")]
    if not notes:
        pytest.skip("the fixture has no coverage notes")
    findings, _ = apply(before.findings, [_x(notes[0].rule_id, "*")], datetime(2026, 10, 6, tzinfo=UTC))
    assert not any(f.exceptions for f in findings if f.rule_id.startswith("ICP-"))


def test_an_accepted_risk_is_not_a_fix_in_the_progress_comparison():
    from icp.delta.compare import compare

    _, before = _assessed(None)
    _, after = _assessed([_x("M365-ADM-001", "*")])
    delta = compare(before.findings, after.findings)
    assert not any(f.rule_id == "M365-ADM-001" for f in delta.resolved + delta.improved)


def test_a_bad_exceptions_file_stops_the_run(tmp_path, monkeypatch):
    from icp.cli import cli

    bad = tmp_path / "exceptions.yaml"
    bad.write_text("exceptions:\n  - rule: M365-ADM-001\n", encoding="utf-8")
    monkeypatch.setenv("ICP_EXCEPTIONS_FILE", str(bad))
    monkeypatch.setenv("ICP_SNAPSHOT_DIR", str(tmp_path / "s"))
    monkeypatch.setenv("ICP_OUTPUT_DIR", str(tmp_path / "o"))
    monkeypatch.setenv("ICP_TENANT_ID", "dev-icp")
    monkeypatch.chdir(Path(__file__).resolve().parents[2])
    assert CliRunner().invoke(cli, ["collect", "--fixtures"], obj={}).exit_code == 0
    result = CliRunner().invoke(cli, ["assess"], obj={})
    assert result.exit_code == 1 and "missing entity" in result.output
