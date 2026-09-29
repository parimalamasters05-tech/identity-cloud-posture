"""A degraded collector must silence only the rules that actually need it.

Found against a real tenant: the 2SV usage report was empty (it lags several
days on a new tenant), and the whole MFA family was skipped -- including the two
rules that only read enrollment from the Directory API. The report said
"enrollment state is still assessed" while assessing nothing.
"""

from __future__ import annotations

from tests.conftest import FIXTURE_NOW

from icp.models.enums import Assessability, Severity
from icp.models.snapshot import CollectionError
from icp.normalizers.google import normalize
from icp.rules import assess


def _without_usage_report(snapshot):
    artifacts = {k: v for k, v in snapshot.artifacts.items() if k != "google.mfa"}
    return snapshot.model_copy(
        update={
            "artifacts": artifacts,
            "errors": (
                CollectionError(
                    collector="google.mfa",
                    assessability=Assessability.NOT_ASSESSABLE_LICENSE,
                    message="No populated 2SV usage report was available in the last five days.",
                ),
            ),
        }
    )


def test_no_user_list_is_not_reported_as_no_apps(snapshot, matrix):
    """If the users collector fails, the OAuth collector has nobody to enumerate.
    That used to produce an empty grant list -- "Third-party application
    access: no issues found" -- a pass on the headline check."""
    import pytest

    from icp.collectors.base import CollectorError
    from icp.collectors.google.oauth import OAuthTokensCollector

    class _NoUsers:
        def __init__(self) -> None:
            self.known_users: list = []

    with pytest.raises(CollectorError):
        OAuthTokensCollector().collect(_NoUsers())  # type: ignore[arg-type]

    artifacts = {
        k: v for k, v in snapshot.artifacts.items() if k not in ("google.users", "google.oauth_tokens")
    }
    degraded = snapshot.model_copy(
        update={
            "artifacts": artifacts,
            "errors": (
                CollectionError(
                    collector="google.users",
                    assessability=Assessability.NOT_ASSESSABLE_PERMISSION,
                    message="Access denied (403).",
                ),
            ),
        }
    )
    tenant = normalize(degraded)
    result = assess(tenant, matrix=matrix, now=FIXTURE_NOW)

    assert "oauth_grants" in result.unassessable
    assert not any(f.rule_id.startswith("GWS-OAU") for f in result.findings)


def _with_failed_oauth_users(snapshot, count: int):
    oauth = dict(snapshot.artifacts["google.oauth_tokens"])
    users = snapshot.artifacts["google.users"][:count]
    oauth["failed_users"] = [{"user_id": u["id"], "error": "HttpError 500"} for u in users]
    oauth["users_enumerated"] = oauth["users_total"] - count
    return snapshot.model_copy(update={"artifacts": {**snapshot.artifacts, "google.oauth_tokens": oauth}})


def test_accounts_whose_grants_could_not_be_read_are_named(snapshot, matrix):
    """Previously recorded in the snapshot and never shown to the reader."""
    tenant = normalize(_with_failed_oauth_users(snapshot, 3))
    result = assess(tenant, matrix=matrix, now=FIXTURE_NOW)

    notes = [f for f in result.findings if f.rule_id == "ICP-COVERAGE-003"]
    assert len(notes) == 1
    assert notes[0].severity == Severity.INFO
    assert len([e for e in notes[0].affected_entities if e.kind == "user"]) == 3
    assert "3 of" in result.partial_coverage["partial:google.oauth_tokens"]
    # The checks still ran on everyone else.
    assert any(f.rule_id == "GWS-OAU-002" for f in result.findings)


def test_a_partly_assessed_area_is_never_listed_as_clean(snapshot, matrix):
    from icp.models.enums import CheckFamily
    from icp.reporting.renderer import ReportRenderer

    tenant = normalize(_with_failed_oauth_users(snapshot, 1))
    result = assess(tenant, matrix=matrix, now=FIXTURE_NOW)
    clean = type(result)(
        findings=[
            f
            for f in result.findings
            if f.check_family != CheckFamily.OAUTH_GRANTS or f.rule_id.startswith("ICP-")
        ],
        rules_run=result.rules_run,
        unassessable=result.unassessable,
        partial_coverage=result.partial_coverage,
    )
    context = ReportRenderer().build_context(tenant, clean, client_name="X", assessor="Y")
    assert "Third-party application access" not in [a["title"] for a in context["passed_areas"]]


def test_a_truncated_listing_becomes_a_coverage_note(snapshot, matrix):
    truncated = snapshot.model_copy(
        update={"partial": {"google.public_drive_items": "Stopped after 500 pages; more existed."}}
    )
    result = assess(normalize(truncated), matrix=matrix, now=FIXTURE_NOW)
    assert "partial:google.public_drive_items" in result.partial_coverage
    assert any(f.rule_id == "ICP-COVERAGE-003" for f in result.findings)


def test_disabled_policy_api_reaches_the_report_with_its_reason(snapshot, matrix):
    """The sharing-warning check says *why* it did not run, not just that it didn't."""
    artifacts = {k: v for k, v in snapshot.artifacts.items() if k != "google.workspace_policies"}
    degraded = snapshot.model_copy(
        update={
            "artifacts": artifacts,
            "errors": (
                CollectionError(
                    collector="google.workspace_policies",
                    assessability=Assessability.NOT_ASSESSABLE_PERMISSION,
                    message="The Cloud Identity API is not enabled on the GCP project.",
                ),
            ),
        }
    )
    result = assess(normalize(degraded), matrix=matrix, now=FIXTURE_NOW)

    assert not any(f.rule_id == "GWS-SHR-002" for f in result.findings)
    assert "Cloud Identity API is not enabled" in result.unassessable["GWS-SHR-002"]
    assert any(f.rule_id == "GWS-SHR-001" for f in result.findings), "the rest of the family still runs"


def test_enrollment_rules_still_run_when_usage_report_is_missing(snapshot, matrix):
    result = assess(normalize(_without_usage_report(snapshot)), matrix=matrix, now=FIXTURE_NOW)
    fired = {f.rule_id for f in result.findings}

    assert "GWS-MFA-001" in fired
    assert "GWS-MFA-002" in fired


def test_method_strength_is_a_coverage_note_not_a_false_positive(snapshot, matrix):
    """Without security-key counts every enrolled admin looks key-less."""
    result = assess(normalize(_without_usage_report(snapshot)), matrix=matrix, now=FIXTURE_NOW)

    assert not any(f.rule_id == "GWS-MFA-003" for f in result.findings)
    notes = [
        f
        for f in result.findings
        if f.rule_id == "ICP-COVERAGE-002" and f.affected_entities[0].id == "GWS-MFA-003"
    ]
    assert len(notes) == 1
    assert notes[0].severity == Severity.INFO
    assert "GWS-MFA-003" in result.unassessable
    assert "mfa_coverage" not in result.unassessable
