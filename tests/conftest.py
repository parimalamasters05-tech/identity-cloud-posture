"""Shared test fixtures.

Everything runs offline against the frozen fixture set. No test in this suite
touches a network or needs a credential, which is what makes the rule suite safe
to run in CI and fast enough to run on every save.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from icp.collectors.google import load_fixture_snapshot
from icp.normalizers.base import NormalizedTenant
from icp.normalizers.google import normalize
from icp.reporting.remediation import RemediationLibrary
from icp.risk.severity import RiskMatrix
from icp.rules import assess
from icp.rules.engine import AssessmentResult

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The fixtures encode "today" as 2026-09-01. Pinning `now` keeps every
#: age-based rule deterministic; without it, dormancy findings would silently
#: change as the calendar moved and the suite would rot.
FIXTURE_NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="session")
def fixture_dir() -> Path:
    return REPO_ROOT / "fixtures" / "google"


@pytest.fixture(scope="session")
def snapshot(fixture_dir: Path):
    return load_fixture_snapshot(fixture_dir, tenant_id="dev-icp")


@pytest.fixture(scope="session")
def tenant(snapshot) -> NormalizedTenant:
    return normalize(snapshot)


@pytest.fixture(scope="session")
def matrix() -> RiskMatrix:
    return RiskMatrix.load_default(REPO_ROOT / "config")


@pytest.fixture(scope="session")
def library() -> RemediationLibrary:
    return RemediationLibrary.load_default(REPO_ROOT / "config")


@pytest.fixture(scope="session")
def result(tenant: NormalizedTenant, matrix: RiskMatrix) -> AssessmentResult:
    return assess(tenant, matrix=matrix, now=FIXTURE_NOW)


@pytest.fixture(scope="session")
def findings_by_rule(result: AssessmentResult) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for finding in result.findings:
        grouped.setdefault(finding.rule_id, []).append(finding)
    return grouped


def entity_labels(finding) -> set[str]:
    return {e.label for e in finding.affected_entities}
