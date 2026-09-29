"""GWS-OAU-005 fires only on what the token audit log shows.

The previous version called every broad app "dormant", because Google's token
listing has no last-use field and missing data read as "unused". These tests
pin each way the data can be missing to "not assessed", never to a finding.
"""

from __future__ import annotations

import pytest
from tests.conftest import FIXTURE_NOW

from icp.normalizers.google import normalize
from icp.rules import assess

RULE = "GWS-OAU-005"


def _run(snapshot, matrix, **token_activity_overrides):
    artifacts = dict(snapshot.artifacts)
    if token_activity_overrides.pop("_drop", False):
        artifacts.pop("google.token_activity")
    else:
        artifacts["google.token_activity"] = {
            **snapshot.artifacts["google.token_activity"],
            **token_activity_overrides,
        }
    return assess(
        normalize(snapshot.model_copy(update={"artifacts": artifacts})), matrix=matrix, now=FIXTURE_NOW
    )


def _fired(result) -> bool:
    return any(f.rule_id == RULE for f in result.findings)


def test_log_with_only_consent_events_is_not_assessed(snapshot, matrix):
    """The real dev tenant: 121 authorize and 12 revoke events, no usage."""
    result = _run(
        snapshot,
        matrix,
        activity_recorded=False,
        event_names={"authorize": 121, "revoke": 12},
        apps=[],
    )
    assert not _fired(result)
    assert "not when they were used" in result.unassessable[RULE]


def test_snapshot_without_the_log_is_not_assessed(snapshot, matrix):
    result = _run(snapshot, matrix, _drop=True)
    assert not _fired(result)
    assert RULE in result.unassessable


def test_truncated_read_shorter_than_the_threshold_is_not_assessed(snapshot, matrix):
    """50 pages of heavy usage might only reach back a month. Absence of use in
    a month says nothing about 90 days."""
    result = _run(snapshot, matrix, truncated=True, oldest_event="2026-08-01T00:00:00.000Z")
    assert not _fired(result)
    assert "read back to 2026-08-01" in result.unassessable[RULE]


def test_truncated_read_that_still_covers_the_threshold_is_assessed(snapshot, matrix):
    result = _run(snapshot, matrix, truncated=True, oldest_event="2026-04-01T00:00:00.000Z")
    assert _fired(result)


def test_an_app_authorized_recently_is_not_dormant(snapshot, matrix):
    """Consented last month and not yet used: new, not abandoned."""
    apps = [
        {**a, "last_authorized": "2026-08-20T00:00:00.000Z"} if a["app_name"] == "InboxCleaner Pro" else a
        for a in snapshot.artifacts["google.token_activity"]["apps"]
    ]
    assert not _fired(_run(snapshot, matrix, apps=apps))


@pytest.mark.parametrize("days_ago,fires", [(89, False), (91, True)])
def test_threshold_boundary(snapshot, matrix, days_ago, fires):
    from datetime import timedelta

    last = (FIXTURE_NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    apps = [
        {**a, "last_activity": last, "last_authorized": None} if a["app_name"] == "InboxCleaner Pro" else a
        for a in snapshot.artifacts["google.token_activity"]["apps"]
    ]
    assert _fired(_run(snapshot, matrix, apps=apps)) is fires
