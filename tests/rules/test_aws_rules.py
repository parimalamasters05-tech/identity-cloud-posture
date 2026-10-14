"""AWS: Prowler's results, imported and turned into this tool's findings.

The fixture is real Prowler output: written by Prowler 5.45.0's own Finding
model and OCSF writer (tools/make_prowler_fixture.py) for a made-up account
with planted problems, the AWS counterpart of the seeded Google and Microsoft
tenants.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import REPO_ROOT

from icp.collectors.aws import ProwlerImportError, import_prowler
from icp.models.enums import Platform
from icp.normalizers import normalize_snapshot
from icp.risk.prowler_map import load as load_map
from icp.rules import all_rules, assess

FIXTURE = REPO_ROOT / "fixtures" / "aws" / "prowler-lab.ocsf.json"


def _run(path: Path = FIXTURE):
    snapshot = import_prowler(path, account_alias="lab")
    tenant = normalize_snapshot(snapshot)
    result = assess(tenant, now=snapshot.collected_at)
    by_rule: dict[str, list] = {}
    for f in result.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    return snapshot, tenant, result, by_rule


@pytest.fixture(scope="module")
def seeded():
    return _run()


# -- the check map ------------------------------------------------------------------


def test_every_mapped_check_exists_in_the_pinned_prowler_and_is_in_the_checks_file():
    """The checks file is what the prowler service runs; it must match the map."""
    mapped = load_map()
    checks_file = json.loads((REPO_ROOT / "config" / "prowler_checks.json").read_text("utf-8"))["aws"]
    assert checks_file == list(mapped.checks)
    assert mapped.prowler_version == "5.45.0"


def test_every_aws_rule_has_a_fix_a_time_estimate_and_known_framework_references():
    import yaml

    from icp.reporting.remediation import RemediationLibrary

    library = RemediationLibrary.load_default()
    effort = yaml.safe_load((REPO_ROOT / "config" / "risk_matrix.yaml").read_text("utf-8"))["effort_hours"]
    framework = yaml.safe_load((REPO_ROOT / "config" / "framework_mapping.yaml").read_text("utf-8"))
    rules = [r for r in all_rules() if Platform.AWS in r.platforms]
    assert len(rules) == len(load_map().rules) == 21
    for rule in rules:
        assert rule.remediation_key in library.entries, rule.rule_id
        assert rule.remediation_key in effort, rule.rule_id
        assert set(rule.framework_refs) <= set(framework["subcategories"]), rule.rule_id
    assert {r.check_family for r in rules} == {r.check_family for r in all_rules()}, "all seven families"


# -- import -----------------------------------------------------------------------


def test_import_keeps_only_mapped_checks_and_the_fields_a_finding_needs(seeded):
    snapshot, tenant, _, _ = seeded
    rows = snapshot.artifacts["aws.prowler"]["results"]
    assert "iam_password_policy_minimum_length_14" not in {r["check_id"] for r in rows}
    assert set(rows[0]) == {
        "check_id",
        "status",
        "resource_uid",
        "resource_name",
        "resource_type",
        "region",
        "detail",
    }
    assert snapshot.platform == Platform.AWS
    assert snapshot.artifacts["aws.account"] == {"account_id": "111122223333", "alias": "lab"}
    assert snapshot.artifacts["aws.prowler"]["prowler_version"] == "5.45.0"
    assert snapshot.scopes_used == ("SecurityAudit", "ViewOnlyAccess")
    assert snapshot.api_calls == ()  # this tool never contacts AWS
    assert snapshot.collected_at.isoformat() == "2026-10-10T14:00:00+00:00"
    assert tenant.organization_name == "lab"


def test_a_file_that_is_not_prowler_output_is_refused(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(ProwlerImportError, match="json-ocsf"):
        import_prowler(bad)


def test_results_for_two_accounts_are_refused(tmp_path):
    data = json.loads(FIXTURE.read_text("utf-8"))
    data[1]["cloud"]["account"]["uid"] = "999999999999"
    two = tmp_path / "two.json"
    two.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ProwlerImportError, match="one account at a time"):
        import_prowler(two)


# -- findings ------------------------------------------------------------------------


def test_every_planted_problem_is_found(seeded):
    _, _, _, by_rule = seeded
    expected = {
        "AWS-MFA-001": ["the root user"],
        "AWS-MFA-002": ["alice.test"],
        "AWS-ADM-003": ["bob.admin"],
        "AWS-ADM-004": ["everything-policy"],
        "AWS-STA-002": ["carol.svc"],
        "AWS-SHR-001": ["icp-test-public"],
        "AWS-SHR-004": ["111122223333"],
        "AWS-LOG-001": ["us-east-1", "us-west-2"],
        "AWS-OAU-001": ["icp-test-private"],
        "AWS-OAU-003": ["us-east-1", "us-west-2"],
    }
    found = {
        rule: [e.label for e in findings[0].affected_entities]
        for rule, findings in by_rule.items()
        if findings[0].severity.value != "info"
    }
    assert found == expected


def test_passed_checks_raise_nothing(seeded):
    _, _, _, by_rule = seeded
    for rule in ("AWS-ADM-001", "AWS-ADM-002", "AWS-STA-001", "AWS-STA-003", "AWS-SVC-001", "AWS-SHR-002"):
        assert rule not in by_rule


def test_the_hardware_key_finding_is_not_repeated_when_the_root_user_has_no_second_step(seeded):
    """Prowler fails both root checks; saying "use a key, not an app" to a root
    user with nothing at all would be noise."""
    _, _, _, by_rule = seeded
    assert "AWS-MFA-001" in by_rule and "AWS-MFA-003" not in by_rule


def test_scoring_titles_and_evidence_read_plainly(seeded):
    from tests.reporting.test_plain_language import EVERYWHERE, _violations

    _, _, _, by_rule = seeded
    [root] = by_rule["AWS-MFA-001"]
    assert root.severity.value == "critical" and root.privileged_entity_count == 1
    assert root.title == "The account's root user has no second sign-in step"
    [regions] = by_rule["AWS-LOG-001"]
    assert regions.title == "Account activity is not being recorded in 2 AWS regions"
    problems = []
    for findings in by_rule.values():
        for f in findings:
            problems += _violations(f.title, EVERYWHERE)
            problems += [p for e in f.evidence for p in _violations(e.summary, EVERYWHERE)]
    assert problems == []
    # Prowler's own wording is kept as the technical record, not shown as the sentence.
    assert root.evidence[0].observed_values["prowler_result"] == "MFA is not enabled for root account."


def test_finding_ids_are_stable_across_imports():
    first = {f.finding_id for f in _run()[2].findings}
    second = {f.finding_id for f in _run()[2].findings}
    assert first == second


def test_a_service_prowler_returned_nothing_for_is_not_assessed_not_clean(tmp_path):
    data = [i for i in json.loads(FIXTURE.read_text("utf-8")) if i["metadata"]["event_code"][:3] != "s3_"]
    path = tmp_path / "no-s3.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    snapshot, _, result, by_rule = _run(path)
    assert "aws.s3" in snapshot.degraded_collectors()
    assert "AWS-SHR-001" not in by_rule and "AWS-OAU-001" not in by_rule
    assert {"AWS-SHR-001", "AWS-SHR-004", "AWS-OAU-001"} <= set(result.unassessable)
    assert "AWS-MFA-001" in by_rule  # IAM still read
