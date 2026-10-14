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
#: Prowler's log from the same run: no refused reads.
CLEAN_LOG = REPO_ROOT / "fixtures" / "aws" / "prowler-lab.log"
#: As logged live: an organization policy refusing two reads.
REFUSED_LOG = REPO_ROOT / "fixtures" / "aws" / "prowler-refused.log"

_DEFAULT = object()


def _run(path: Path = FIXTURE, log: object = _DEFAULT):
    log_path = CLEAN_LOG if log is _DEFAULT else log
    snapshot = import_prowler(path, account_alias="lab", log_path=log_path)  # type: ignore[arg-type]
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


# -- Found on the first live run (14 Oct 2026) ----------------------------------------


def test_a_read_refused_by_an_organization_policy_is_not_assessed_not_a_pass():
    """Live: an organization's service control policy denied iam:GetLoginProfile.
    Prowler logged it and reported every user as having no console password,
    so the console checks passed on data it never got."""
    snapshot, _, result, by_rule = _run(log=REFUSED_LOG)
    assert snapshot.artifacts["aws.denied"]["iam:GetLoginProfile"]["by_organization_policy"] is True
    for rule in ("AWS-MFA-002", "AWS-STA-001"):
        assert rule not in by_rule, rule
        assert rule in result.unassessable, rule
    # Per region: refused in us-east-1 only, so us-west-2 is still reported.
    assert [e.label for e in by_rule["AWS-OAU-003"][0].affected_entities] == ["us-west-2"]
    reason = result.unassessable["AWS-MFA-002"]
    assert "iam:GetLoginProfile" in reason and "organization" in reason
    assert "AWS-ADM-003" in by_rule  # checks that do not need the refused read still run


def test_without_prowlers_log_a_refused_read_cannot_be_ruled_out():
    _, _, result, by_rule = _run(log=None)
    assert "AWS-MFA-002" not in by_rule and "AWS-MFA-002" in result.unassessable
    assert "log was not imported" in result.unassessable["AWS-MFA-002"]


def test_no_result_for_the_root_checks_is_not_assessed_not_clean(tmp_path):
    """Prowler 5.45 checks root MFA only when the root user has access keys; on
    the live account it returned nothing, which must not read as a pass."""
    data = [
        i
        for i in json.loads(FIXTURE.read_text("utf-8"))
        if not i["metadata"]["event_code"].startswith("iam_root_")
    ]
    path = tmp_path / "no-root.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    _, _, result, by_rule = _run(path)
    assert "AWS-MFA-001" not in by_rule and "AWS-MFA-001" in result.unassessable
    assert "IAM > Dashboard" in result.unassessable["AWS-MFA-001"]
    assert "AWS-ADM-001" not in result.unassessable  # no root key result means no root keys


def test_a_public_bucket_is_not_also_reported_as_shared_with_another_account(tmp_path):
    """Live: Prowler counts a public bucket policy ("*") as cross-account access."""
    data = json.loads(FIXTURE.read_text("utf-8"))
    extra = next(
        i
        for i in data
        if i["metadata"]["event_code"] == "s3_bucket_cross_account_access" and i["status_code"] == "FAIL"
    )
    public = json.loads(json.dumps(extra))
    public["resources"][0]["uid"] = "arn:aws:s3:::icp-test-public"
    public["resources"][0]["name"] = "icp-test-public"
    path = tmp_path / "public-also-cross.json"
    path.write_text(json.dumps([*data, public]), encoding="utf-8")
    _, _, _, by_rule = _run(path)
    assert [e.label for e in by_rule["AWS-OAU-001"][0].affected_entities] == ["icp-test-private"]


def _trail_refusal_log(tmp_path, regions):
    """As logged live: listing trails refused per region by an organization policy."""
    lines = [
        f'{{"level": "ERROR", "message": "{region} -- ClientError[120]: An error occurred (AccessDeniedException) '
        f"when calling the DescribeTrails operation: User: arn:aws:sts::111122223333:assumed-role/icp-assessment/"
        f"ProwlerAssessmentSession is not authorized to perform: cloudtrail:DescribeTrails on resource: "
        f'arn:aws:cloudtrail:{region}:111122223333:trail/* with an explicit deny in a service control policy"}}'
        for region in regions
    ]
    path = tmp_path / "prowler.log"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def test_regions_aws_refused_to_show_are_left_out_and_named(tmp_path):
    """Live: listing trails was refused in 16 of 17 regions, and Prowler
    reported each of them as having no trail."""
    _, tenant, result, by_rule = _run(log=_trail_refusal_log(tmp_path, ["us-west-2"]))
    [finding] = by_rule["AWS-LOG-001"]
    assert [e.label for e in finding.affected_entities] == ["us-east-1"]
    assert finding.title == "Account activity is not being recorded in 1 AWS region"
    [gap] = [g for g in tenant.coverage_gaps if g.key == "aws-refused-aws-log-001"]
    assert "us-west-2" in gap.reason and "covers us-east-1 only" in gap.reason
    assert gap.key in result.partial_coverage


def test_refused_in_every_region_is_not_assessed(tmp_path):
    _, _, result, by_rule = _run(log=_trail_refusal_log(tmp_path, ["us-east-1", "us-west-2"]))
    assert "AWS-LOG-001" not in by_rule and "AWS-LOG-001" in result.unassessable


def test_an_area_refused_outright_says_why(tmp_path):
    data = [
        i
        for i in json.loads(FIXTURE.read_text("utf-8"))
        if not i["metadata"]["event_code"].startswith("access")
    ]
    path = tmp_path / "no-analyzer.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    snapshot, _, result, _ = _run(path, log=REFUSED_LOG)
    [error] = [e for e in snapshot.errors if e.collector == "aws.accessanalyzer"]
    assert "access-analyzer:ListAnalyzers" in error.message and "organization" in error.message
    assert "Not assessed" not in result.unassessable.get("AWS-OAU-003", "")


def test_a_not_assessed_note_does_not_read_like_a_finding():
    rules = {r.rule_id: r for r in all_rules() if Platform.AWS in r.platforms}
    assert rules["AWS-MFA-002"].title == "AWS users can sign in to the console with a password alone"
    assert not any(r.title[0].isdigit() for r in rules.values())


def test_the_aws_report_reads_plainly_on_the_cover_and_in_clean_areas(tmp_path):
    """Live report: the cover said "Not fully read: aws.accessanalyzer", and the
    clean areas said "aws users" (the whole title was lowercased)."""
    import re

    from tests.reporting.test_plain_language import EVERYWHERE, _text, _violations

    from icp.reporting.renderer import ReportRenderer

    data = [
        i
        for i in json.loads(FIXTURE.read_text("utf-8"))
        if not i["metadata"]["event_code"].startswith("access")
    ]
    path = tmp_path / "no-analyzer.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    _, tenant, result, _ = _run(path, log=REFUSED_LOG)
    renderer = ReportRenderer()
    context = renderer.build_context(tenant, result, client_name="Lab", assessor="T")
    cover = _text(renderer.env.get_template("partials/cover.html").render(**context))
    assert "AWS IAM Access Analyzer" in cover and _violations(cover, EVERYWHERE) == []
    findings = _text(renderer.env.get_template("partials/findings.html").render(**context))
    looked_for = " ".join(re.findall(r"We looked for: [^.]*", findings))
    assert looked_for and "aws " not in looked_for


def test_a_title_mid_sentence_keeps_its_acronym():
    from icp.reporting.plain import sentence_case

    assert sentence_case("AWS users have access keys") == "AWS users have access keys"
    assert sentence_case("Super-administrators") == "super-administrators"
    assert sentence_case("OAuth grants") == "OAuth grants"


# -- Found in the second live round (14 Oct 2026) ------------------------------------


def test_an_inline_policy_is_named_with_the_user_it_is_on():
    from icp.rules.aws import _label

    mapped = next(r for r in load_map().rules if r.rule_id == "AWS-ADM-004")
    row = {
        "resource_type": "AwsIamPolicy",
        "resource_name": "test-dev/test-inline-everything",
        "resource_uid": "",
    }
    assert _label(row, mapped) == "test-inline-everything (inline, on test-dev)"


def test_the_report_says_roles_used_by_aws_services_were_not_checked():
    """Live: a Lambda role with AdministratorAccess was not reported, because
    Prowler leaves out roles that AWS services use. The report must not imply
    they were covered."""
    from icp.reporting.platform_text import AWS

    assert "Lambda" in AWS.licence_note and "not checked" in AWS.licence_note
    assert not any("services are allowed" in line for line in AWS.examined)
    svc = next(r for r in load_map().rules if r.rule_id == "AWS-SVC-001")
    assert "switch into" in svc.one
