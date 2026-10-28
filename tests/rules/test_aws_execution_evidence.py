"""AWS: a check that returned nothing is clean only if it demonstrably ran.

Review, 27 Oct 2026: completeness was checked per service, so if IAM returned
results for some checks but one mapped check returned nothing (crashed, or
renamed in a Prowler upgrade), that check read as clean. And only "not
authorized" log lines were read. Prowler emits nothing both for a check that
found nothing to check and for one that failed; its log tells them apart.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.rules.test_aws_rules import CLEAN_LOG, _run

from icp.collectors.aws import read_scan_errors
from icp.models.enums import RuleOutcome
from icp.risk.prowler_map import load as load_map

pytestmark = pytest.mark.security

CHECKS = set(load_map().checks)


def _log(tmp_path: Path, *messages: tuple[str, str]) -> Path:
    """A Prowler log (JSON lines) with these (module, message) errors after the clean one."""
    path = tmp_path / "prowler.log"
    lines = [CLEAN_LOG.read_text("utf-8").strip()]
    lines += [
        json.dumps(
            {"timestamp": "2026-10-10 14:00:05,000", "level": "ERROR", "module": module, "message": message}
        )
        for module, message in messages
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_a_crashed_check_is_not_assessed_although_its_service_returned_results(tmp_path):
    """The review's case: IAM returned results, one IAM check crashed."""
    log = _log(tmp_path, ("check", "iam_user_accesskey_unused -- KeyError[42]: 'access_key_1_active'"))
    _, _, result, _ = _run(log=log)
    assert result.outcomes["AWS-STA-002"] == RuleOutcome.UNAVAILABLE
    assert "AWS-STA-002" in result.unassessable
    assert "did not run properly" in result.unassessable["AWS-STA-002"]
    assert result.outcomes["AWS-MFA-002"] != RuleOutcome.UNAVAILABLE  # other IAM checks unaffected


def test_a_check_prowler_does_not_have_is_not_assessed(tmp_path):
    """A renamed check after a Prowler upgrade returns nothing and logs this."""
    log = _log(
        tmp_path,
        (
            "check",
            "Check 'iam_role_cross_account_readonlyaccess_policy' was not found for the AWS provider",
        ),
    )
    _, _, result, _ = _run(log=log)
    assert result.outcomes["AWS-OAU-002"] == RuleOutcome.UNAVAILABLE


def test_an_absent_check_with_a_clean_log_ran_and_found_nothing_to_check(tmp_path):
    """Prowler's role check emits only for roles holding ReadOnlyAccess: none in the lab."""
    _, _, result, _ = _run(log=_log(tmp_path))
    assert result.outcomes["AWS-OAU-002"] in (RuleOutcome.PASSED, RuleOutcome.PARTIAL)


def test_without_the_log_an_absent_check_is_not_assumed_clean():
    _, _, result, _ = _run(log=None)
    assert result.outcomes["AWS-OAU-002"] == RuleOutcome.UNAVAILABLE
    assert "cannot be told apart" in result.unassessable["AWS-OAU-002"]


def test_a_service_error_other_than_a_refusal_holds_back_that_services_rules(tmp_path):
    log = _log(tmp_path, ("iam_service", "us-east-1 -- ThrottlingException[88]: Rate exceeded"))
    _, _, result, _ = _run(log=log)
    iam_rules = [r.rule_id for r in load_map().rules if r.service == "iam"]
    assert all(result.outcomes[r] == RuleOutcome.UNAVAILABLE for r in iam_rules)
    assert all(
        result.outcomes[r.rule_id] != RuleOutcome.UNAVAILABLE for r in load_map().rules if r.service == "s3"
    )


def test_a_regional_service_error_leaves_out_only_that_region_and_says_so(tmp_path):
    snapshot, tenant, result, _ = _run(log=_log(tmp_path))
    trail_regions = sorted(
        {
            r["region"]
            for r in snapshot.artifacts["aws.prowler"]["results"]
            if r["check_id"] == "cloudtrail_multi_region_enabled"
        }
    )
    assert len(trail_regions) >= 2, "the fixture needs two regions"
    log = _log(
        tmp_path,
        ("cloudtrail_service", f"{trail_regions[0]} -- EndpointConnectionError[12]: Could not connect"),
    )
    _, tenant, result, _ = _run(log=log)
    assert result.outcomes["AWS-LOG-001"] != RuleOutcome.UNAVAILABLE
    assert any(
        g.key == "aws-errored-aws-log-001" and trail_regions[0] in g.reason for g in tenant.coverage_gaps
    )


def test_refused_reads_and_unrelated_errors_do_not_count_as_check_failures(tmp_path):
    log = _log(
        tmp_path,
        (
            "iam_service",
            "us-east-1 -- ClientError[297]: An error occurred (AccessDenied) when calling the X operation: User: arn is not authorized to perform: iam:ListSAMLProviders on resource: x",
        ),
        ("check", "Unable to retrieve ulimit default settings"),
    )
    found = read_scan_errors(log, CHECKS)
    assert found["checks"] == {} and found["services"] == {}
    assert found["other"] == ["Unable to retrieve ulimit default settings"]


def test_a_plain_text_log_line_is_still_read(tmp_path):
    """If Prowler's log format changes, errors still count."""
    log = tmp_path / "prowler.log"
    log.write_text(
        "2026-10-10 14:00:05 ERROR iam_user_accesskey_unused -- KeyError[42]: boom\n", encoding="utf-8"
    )
    found = read_scan_errors(log, CHECKS)
    assert list(found["checks"]) == ["iam_user_accesskey_unused"]
