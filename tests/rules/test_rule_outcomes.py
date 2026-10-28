"""Every rule has an outcome, and a crashed rule is never a pass (review, 27 Oct 2026).

Reproduced: a rule that raised was recorded in rules_failed, but the report's
clean-areas list excluded only rules marked not assessed, so the crashed rule
was listed as a passed check.
"""

from __future__ import annotations

import re

import pytest
from tests.conftest import FIXTURE_NOW

from icp.models.enums import CheckFamily, RuleOutcome
from icp.normalizers.google import normalize
from icp.reporting.renderer import ReportRenderer
from icp.rules import assess
from icp.rules.base import all_rules

pytestmark = pytest.mark.security

#: The area made clean, then given one crashing check.
AREA = CheckFamily.LOGGING_READINESS


def _boom(self, tenant, ctx):
    raise RuntimeError("simulated defect")


def _nothing(self, tenant, ctx):
    return []


@pytest.fixture
def area_rules(snapshot):
    tenant = normalize(snapshot)
    rules = [r for r in all_rules() if r.check_family == AREA and tenant.platform in r.platforms]
    assert len(rules) >= 2, "the area needs two checks: one to crash, one that passes"
    return tenant, rules


def _run(monkeypatch, tenant, rules, matrix, *, crash: bool):
    for rule in rules:
        monkeypatch.setattr(rule, "evaluate", _nothing)
    if crash:
        monkeypatch.setattr(rules[0], "evaluate", _boom)
    result = assess(tenant, matrix=matrix, now=FIXTURE_NOW)
    renderer = ReportRenderer()
    return result, renderer, renderer.build_context(tenant, result, client_name="X", assessor="Y")


def _area_listed(context, rules) -> bool:
    titles = {r.title for r in rules}
    return any(titles & set(area["checks"]) for area in context["passed_areas"])


def test_every_rule_of_the_platform_has_exactly_one_outcome(snapshot, matrix):
    tenant = normalize(snapshot)
    result = assess(tenant, matrix=matrix, now=FIXTURE_NOW)
    assert set(result.outcomes) == {r.rule_id for r in all_rules() if tenant.platform in r.platforms}
    assert result.rules_with(RuleOutcome.FAILED) == []


def test_the_clean_area_is_listed_when_every_check_passes(monkeypatch, area_rules, matrix):
    """The control for the test below: same area, no crash."""
    tenant, rules = area_rules
    result, _, context = _run(monkeypatch, tenant, rules, matrix, crash=False)
    assert all(result.outcomes[r.rule_id] == RuleOutcome.PASSED for r in rules)
    assert _area_listed(context, rules)


def test_a_crashed_rule_is_failed_reported_and_its_area_never_listed_as_clean(
    monkeypatch, area_rules, matrix
):
    tenant, rules = area_rules
    result, renderer, context = _run(monkeypatch, tenant, rules, matrix, crash=True)

    assert result.outcomes[rules[0].rule_id] == RuleOutcome.FAILED
    assert result.outcomes[rules[1].rule_id] == RuleOutcome.PASSED
    assert [r for r, _ in result.rules_failed] == [rules[0].rule_id]
    [note] = [f for f in result.findings if f.rule_id == "ICP-COVERAGE-004"]
    assert note.affected_entities[0].id == rules[0].rule_id

    # Not the crashed check, and not the area: its other check passing is not enough.
    assert not _area_listed(context, rules)
    # Said on the cover, prominently.
    assert context["failed_checks"] == [rules[0].title]
    html = re.sub(r"\s+", " ", renderer.env.get_template("report.html").render(**context))
    assert "Checks that did not run" in html and rules[0].title in html


def test_a_crash_rules_out_a_clean_rating(monkeypatch, area_rules, matrix):
    from icp.risk.ranking import posture_rating

    tenant, rules = area_rules
    result, _, _ = _run(monkeypatch, tenant, rules, matrix, crash=True)
    # Only the coverage notes: no other gaps, which alone would rate "Reasonable".
    notes = [f for f in result.findings if f.rule_id.startswith("ICP-COVERAGE")]
    rating, why = posture_rating(notes)
    assert rating == "Incomplete" and "1 check did not run" in why


def test_a_crashed_check_is_not_rechecked_in_the_delta_never_resolved(monkeypatch, snapshot, matrix):
    from icp.delta.compare import compare

    tenant = normalize(snapshot)
    before = assess(tenant, matrix=matrix, now=FIXTURE_NOW).findings
    flagged = next(f for f in before if f.severity.value in ("critical", "high"))
    [rule] = [r for r in all_rules() if r.rule_id == flagged.rule_id]
    monkeypatch.setattr(rule, "evaluate", _boom)
    after = assess(tenant, matrix=matrix, now=FIXTURE_NOW).findings
    delta = compare(before, after)
    assert flagged.finding_id in {f.finding_id for f in delta.not_revalidated}
    assert flagged.finding_id not in {f.finding_id for f in delta.resolved}
