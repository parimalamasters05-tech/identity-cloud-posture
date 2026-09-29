"""The sign-in method report: ask for fields that exist, and never mistake a
rejected request for a report that has not arrived yet.

Found on the dev tenant: the collector asked for "accounts:security_key_count",
which Google does not have. Every day came back HTTP 400 "Invalid parameter
name", the collector treated every 400 as "not ready, try an earlier day", and
the report told the client Google had not produced its data. MFA-003 had never
run for anyone.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from tests.conftest import FIXTURE_NOW, entity_labels

from icp.collectors.base import CollectorError
from icp.collectors.google.mfa import PARAMETERS, MfaCollector
from icp.models.enums import Assessability
from icp.normalizers.google import normalize
from icp.rules import assess


class _HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}")
        self.resp = type("R", (), {"status": status})()
        self.content = json.dumps({"error": {"message": message}}).encode()


class _Client:
    """Answers each date in turn from `answers` (an exception or a report list)."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.requested: list[str] = []

    def service(self, *a, **k):
        return type("S", (), {"userUsageReport": lambda _s: object()})()

    def paginate(self, resource, method, key, **kwargs):
        self.requested.append(kwargs["parameters"])
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


ROW = {
    "entity": {"profileId": "1", "userEmail": "a@x.example"},
    "parameters": [
        {"name": "accounts:num_security_keys", "intValue": "0"},
        {"name": "accounts:num_passkeys_enrolled", "intValue": "1"},
    ],
}


def test_requests_googles_real_field_names():
    assert PARAMETERS == ("accounts:num_security_keys", "accounts:num_passkeys_enrolled")
    client = _Client([[ROW]])
    MfaCollector().collect(client)
    assert client.requested == ["accounts:num_security_keys,accounts:num_passkeys_enrolled"]


def test_an_invalid_field_is_an_error_naming_googles_message_not_a_delay():
    client = _Client(
        [_HttpError(400, "Invalid parameter name security_key_count for application accounts.")]
    )
    with pytest.raises(CollectorError) as caught:
        MfaCollector().collect(client)

    assert caught.value.assessability == Assessability.NOT_ASSESSABLE_ERROR
    assert "Invalid parameter name security_key_count" in str(caught.value)
    assert "had not produced" not in str(caught.value)
    assert len(client.requested) == 1, "must not step back through days on a rejected request"


def test_data_not_yet_available_steps_back_a_day():
    client = _Client(
        [
            _HttpError(
                400, "Data for dates later than 2026-09-27 is not yet available. Please check back later"
            ),
            [ROW],
        ]
    )
    result = MfaCollector().collect(client)
    assert len(client.requested) == 2
    assert result["entries"][0]["num_passkeys_enrolled"] == "1"


def test_no_populated_day_still_reports_the_delay():
    client = _Client([[], [], [], []])
    with pytest.raises(CollectorError, match="had not produced"):
        MfaCollector().collect(client)


# -- the method-strength check, on the planted tenant -------------------------


def _with_report(snapshot, matrix, entries):
    mfa = {**snapshot.artifacts["google.mfa"], "entries": entries}
    tenant = normalize(snapshot.model_copy(update={"artifacts": {**snapshot.artifacts, "google.mfa": mfa}}))
    return tenant, assess(replace(tenant), matrix=matrix, now=FIXTURE_NOW)


def _entries(snapshot, change):
    return [change(dict(e)) for e in snapshot.artifacts["google.mfa"]["entries"]]


def test_a_passkey_counts_as_phishing_resistant(snapshot, matrix):
    """priya.menon is flagged with no key; with a passkey she must not be."""
    entries = _entries(
        snapshot, lambda e: {**e, "num_passkeys_enrolled": 1} if e["email"].startswith("priya.menon") else e
    )
    _, result = _with_report(snapshot, matrix, entries)
    [finding] = [f for f in result.findings if f.rule_id == "GWS-MFA-003"]
    assert not any(label.startswith("priya.menon") for label in entity_labels(finding))


def test_the_evidence_states_which_days_report_it_rests_on(snapshot, matrix):
    """Found on the dev tenant: a passkey added the morning of the run still
    showed as none, because Google's report was two days old, and nothing in
    the report said so."""
    mfa = {**snapshot.artifacts["google.mfa"], "report_date": "2026-09-27"}
    tenant = normalize(snapshot.model_copy(update={"artifacts": {**snapshot.artifacts, "google.mfa": mfa}}))
    result = assess(tenant, matrix=matrix, now=FIXTURE_NOW)

    assert tenant.mfa_report_date == "2026-09-27"
    [finding] = [f for f in result.findings if f.rule_id == "GWS-MFA-003"]
    for evidence in finding.evidence:
        assert "security report for 27 September 2026" in evidence.summary
        assert "one to three days late" in evidence.summary
        assert evidence.observed_values["report_date"] == "2026-09-27"


def test_an_admin_missing_from_a_partial_report_is_not_flagged_but_named(snapshot, matrix):
    """Google marks some days PARTIAL_DATA_AVAILABLE. Missing is unknown, not weak."""
    entries = [
        e for e in snapshot.artifacts["google.mfa"]["entries"] if not e["email"].startswith("priya.menon")
    ]
    tenant, result = _with_report(snapshot, matrix, entries)

    [finding] = [f for f in result.findings if f.rule_id == "GWS-MFA-003"]
    assert not any(label.startswith("priya.menon") for label in entity_labels(finding))
    gap = next(g for g in tenant.coverage_gaps if g.key == "partial:google.mfa")
    assert [label for _, label in gap.missed] == ["priya.menon@dev-icp.example"]
    assert any(f.rule_id == "ICP-COVERAGE-003" for f in result.findings)
