"""Reducing the token audit log to per (app, user) dates."""

from __future__ import annotations

from datetime import UTC, datetime

from icp.collectors.google.token_activity import summarize

START = datetime(2026, 3, 1, tzinfo=UTC)


def event(user: str, client: str, name: str, when: str, app: str = "App") -> dict:
    return {
        "id": {"time": when, "applicationName": "token"},
        "actor": {"email": user, "profileId": "1"},
        "ipAddress": "203.0.113.9",
        "events": [
            {
                "name": name,
                "parameters": [
                    {"name": "client_id", "value": client},
                    {"name": "app_name", "value": app},
                    {"name": "scope", "multiValue": ["openid"]},
                ],
            }
        ],
    }


def test_the_latest_date_of_each_kind_wins():
    items = [
        event("a@x.example", "c1", "activity", "2026-09-01T00:00:00.000Z"),
        event("a@x.example", "c1", "authorize", "2026-05-01T00:00:00.000Z"),
        event("a@x.example", "c1", "activity", "2026-06-01T00:00:00.000Z"),
        event("a@x.example", "c1", "authorize", "2026-04-01T00:00:00.000Z"),
    ]
    [record] = summarize(items, window_start=START, truncated=False)["apps"]
    assert record["last_activity"] == "2026-09-01T00:00:00.000Z"
    assert record["last_authorized"] == "2026-05-01T00:00:00.000Z"
    assert record["last_revoked"] is None


def test_users_and_apps_are_kept_apart():
    items = [
        event("a@x.example", "c1", "activity", "2026-09-01T00:00:00.000Z"),
        event("B@x.example", "c1", "authorize", "2026-08-01T00:00:00.000Z"),
        event("a@x.example", "c2", "revoke", "2026-07-01T00:00:00.000Z"),
    ]
    apps = summarize(items, window_start=START, truncated=False)["apps"]
    assert [(r["client_id"], r["user"]) for r in apps] == [
        ("c1", "a@x.example"),
        ("c1", "b@x.example"),  # lower-cased, to join with the directory
        ("c2", "a@x.example"),
    ]


def test_consent_only_log_does_not_claim_usage_was_recorded():
    items = [
        event("a@x.example", "c1", "authorize", "2026-09-01T00:00:00.000Z"),
        event("a@x.example", "c1", "revoke", "2026-09-02T00:00:00.000Z"),
    ]
    summary = summarize(items, window_start=START, truncated=False)
    assert summary["activity_recorded"] is False
    assert summary["event_names"] == {"authorize": 1, "revoke": 1}


def test_no_ip_address_or_raw_event_is_kept():
    """Data minimization: dates per app and user, nothing about where from."""
    summary = summarize(
        [event("a@x.example", "c1", "activity", "2026-09-01T00:00:00.000Z")],
        window_start=START,
        truncated=False,
    )
    blob = str(summary)
    assert "203.0.113.9" not in blob
    assert "profileId" not in blob and "scope" not in blob


def test_window_and_truncation_are_recorded():
    items = [
        event("a@x.example", "c1", "activity", "2026-09-01T00:00:00.000Z"),
        event("a@x.example", "c1", "activity", "2026-08-01T00:00:00.000Z"),
    ]
    summary = summarize(items, window_start=START, truncated=True)
    assert summary["truncated"] is True
    assert summary["oldest_event"] == "2026-08-01T00:00:00.000Z"
    assert summary["window_start"] == START.isoformat()
