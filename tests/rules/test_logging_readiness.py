"""Family 6: GWS-LOG-002, a reachable audit stream with nothing in it.

LOG-001 (unreadable stream) is covered by the planted suite. LOG-002 had no
test at all until the week-5 review found it.
"""

from __future__ import annotations

from tests.conftest import FIXTURE_NOW, entity_labels

from icp.normalizers.google import normalize
from icp.rules import assess


def _with_streams(snapshot, matrix, **streams):
    audit = snapshot.artifacts["google.audit_readiness"]
    patched = {**audit, "streams": {**audit["streams"], **streams}}
    artifacts = {**snapshot.artifacts, "google.audit_readiness": patched}
    result = assess(
        normalize(snapshot.model_copy(update={"artifacts": artifacts})), matrix=matrix, now=FIXTURE_NOW
    )
    return [f for f in result.findings if f.rule_id == "GWS-LOG-002"]


def test_an_empty_essential_stream_is_reported(snapshot, matrix):
    empty = {"available": True, "event_count_sampled": 0, "oldest_sampled": None, "newest_sampled": None}
    [finding] = _with_streams(snapshot, matrix, admin=empty)

    assert entity_labels(finding) == {"admin activity log"}
    assert "no events in the last 30 days" in finding.title
    # A quiet small tenant is a legitimate explanation; the finding says so.
    assert "expected in a quiet tenant" in finding.evidence[0].summary


def test_an_empty_non_essential_stream_is_not(snapshot, matrix):
    empty = {"available": True, "event_count_sampled": 0, "oldest_sampled": None, "newest_sampled": None}
    assert _with_streams(snapshot, matrix, drive=empty) == []


def test_an_unreadable_stream_is_log_001s_not_log_002s(snapshot, matrix):
    """Unreadable and empty are different problems with different fixes."""
    unreadable = {"available": False, "http_status": 403, "reason": "HttpError"}
    assert _with_streams(snapshot, matrix, admin=unreadable) == []


def test_the_planted_tenant_has_no_empty_stream(findings_by_rule):
    assert "GWS-LOG-002" not in findings_by_rule
