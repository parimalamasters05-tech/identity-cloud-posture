"""Progress since the previous review: the before-and-after, in the report.

Suggested by the review of the first combined report: the delta command showed
the change to the assessor, but nothing showed it to the client.
"""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import timedelta

import pytest
from tests.rules.test_m365_rules import _artifacts, _run

from icp.reporting.progress import build
from icp.reporting.renderer import ReportRenderer


@pytest.fixture(scope="module")
def pair():
    """Before: the seeded tenant. After: the all-users policy switched on."""
    before_tenant, before_result, _ = _run()
    artifacts = deepcopy(_artifacts())
    artifacts["m365.policies"]["conditional_access"][1]["state"] = "enabled"
    after_tenant, after_result, _ = _run(artifacts)
    later = after_tenant.snapshot.model_copy(
        update={
            "collected_at": before_tenant.snapshot.collected_at + timedelta(days=7),
            "snapshot_id": "later",
        }
    )
    after_tenant.snapshot = later
    return (before_tenant, before_result), (after_tenant, after_result)


def test_a_fixed_finding_is_shown_as_resolved_and_the_score_falls(pair):
    progress = build(*pair)
    resolved = [r for r in progress["rows"] if r["key"] == "resolved"]
    assert [r["finding"].rule_id for r in resolved] == ["M365-MFA-004"]
    assert progress["counts"]["resolved"] == 1 and progress["counts"]["new"] == 0
    assert progress["risk"]["current"] < progress["risk"]["previous"]
    assert progress["risk"]["change_pct"] < 0


def test_every_open_finding_appears_once_and_coverage_notes_do_not(pair):
    progress = build(*pair)
    _, (_, after_result) = pair
    open_now = {f.finding_id for f in after_result.findings if f.severity.value != "info"}
    shown = [r["finding"].finding_id for r in progress["rows"] if r["key"] != "resolved"]
    assert sorted(shown) == sorted(open_now)
    assert all(r["finding"].severity.value != "info" for r in progress["rows"])


def test_the_section_is_in_the_report_only_when_asked_for(pair):
    _, (tenant, result) = pair
    renderer = ReportRenderer()
    render = renderer.env.get_template("report.html").render
    without = render(**renderer.build_context(tenant, result, client_name="Lab", assessor="T"))
    assert "Progress since the previous review" not in without
    html = render(
        **renderer.build_context(tenant, result, client_name="Lab", assessor="T", progress=[build(*pair)])
    )
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    assert "Progress since the previous review" in text
    assert "not why" in text  # it reports change, and does not claim the cause
    assert "No longer found." in text and "Nothing requires a second sign-in step" in text
    assert re.search(r"\(down \d+(\.\d+)?%\)", text)


def test_the_two_snapshots_must_be_in_order_and_the_same_platform(pair, tenant, result):
    before, after = pair
    with pytest.raises(ValueError, match="older"):
        build(after, before)
    with pytest.raises(ValueError, match="same platform"):
        build((tenant, result), after)
