"""The week-4 Google Workspace baseline: locked before the multi-platform work.

The brief's week-5 done-when test: "Workspace results are byte-comparable to
the week-4 baseline." Every finding the Google side produces, on both fixture
sets, is recorded in `tests/baselines/google_week4.json` with everything a
client reads: ID, rule, severity, confidence, title, affected accounts, score,
fix, framework references and the evidence wording.

Adding Microsoft 365 or AWS must not change a single field. A failure here
means Google output moved; if the move is intended (a deliberate wording or
scoring change), regenerate and say why in the commit:

    ICP_UPDATE_BASELINE=1 pytest tests/test_google_baseline.py

Locked 6 Oct 2026, after the week-4 submission run (snapshot 08:25 UTC, 29 Sep).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from tests.conftest import REPO_ROOT

from icp.collectors.google import load_fixture_snapshot
from icp.normalizers.google import normalize
from icp.rules import assess

BASELINE = REPO_ROOT / "tests" / "baselines" / "google_week4.json"
SETS = {"synthetic": ("google", "dev-icp"), "frozen-dev": ("google-dev", "dev")}


def _findings(directory: str, tenant_id: str) -> list[dict]:
    snapshot = load_fixture_snapshot(REPO_ROOT / "fixtures" / directory, tenant_id=tenant_id)
    result = assess(normalize(snapshot), now=snapshot.collected_at)
    return sorted(
        (
            {
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "severity": str(f.severity),
                "confidence": str(f.confidence),
                "title": f.title,
                "affected": sorted(e.id for e in f.affected_entities),
                "risk_score": round(f.risk_score, 2),
                "effort_hours": round(f.effort_hours, 2),
                "remediation_key": f.remediation_key,
                "framework_refs": list(f.framework_refs),
                "evidence": [e.summary for e in f.evidence],
            }
            for f in result.findings
        ),
        key=lambda d: (d["rule_id"], d["finding_id"]),
    )


def _current() -> dict[str, list[dict]]:
    return {name: _findings(*where) for name, where in SETS.items()}


def test_google_output_matches_the_week4_baseline():
    current = _current()
    if os.environ.get("ICP_UPDATE_BASELINE") == "1":
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.skip(f"baseline regenerated at {BASELINE}")

    assert BASELINE.exists(), "no baseline: run with ICP_UPDATE_BASELINE=1 once"
    locked = json.loads(BASELINE.read_text(encoding="utf-8"))

    for name in SETS:
        before = {d["finding_id"]: d for d in locked[name]}
        after = {d["finding_id"]: d for d in current[name]}
        assert set(after) == set(before), (
            f"{name}: findings added {sorted(set(after) - set(before))}, "
            f"removed {sorted(set(before) - set(after))}"
        )
        for finding_id, locked_finding in before.items():
            changed = {k for k in locked_finding if locked_finding[k] != after[finding_id][k]}
            assert not changed, (
                f"{name}: {locked_finding['rule_id']} {finding_id} changed: {sorted(changed)}"
            )


def test_the_baseline_covers_both_sets_and_is_not_empty():
    locked = json.loads(Path(BASELINE).read_text(encoding="utf-8"))
    assert set(locked) == set(SETS)
    assert all(locked[name] for name in SETS)
