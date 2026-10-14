"""Write fixtures/aws/prowler-lab.ocsf.json: Prowler results for a made-up
AWS account (111122223333) with planted problems, produced by Prowler's own
Finding model and OCSF writer so the test fixture has Prowler's real shape.

Needs no AWS access. Run inside the Prowler image (the version in
config/prowler_check_map.yaml), from the repository root:

    docker run --rm --user root -v "$PWD/tools:/t:ro" -v "$PWD/fixtures/aws:/out" \
      --entrypoint /home/prowler/.venv/bin/python prowlercloud/prowler:<version> \
      /t/make_prowler_fixture.py /out/prowler-lab.ocsf.json
"""

import io
import sys
from datetime import UTC, datetime
from pathlib import Path

from prowler.lib.check.models import load_check_metadata
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.ocsf.ocsf import OCSF

ACCOUNT = "111122223333"
WHEN = datetime(2026, 10, 10, 14, 0, 0, tzinfo=UTC)
ROOT = f"arn:aws:iam::{ACCOUNT}:root"


def meta(check):
    [path] = Path("/home/prowler/prowler/providers/aws/services").glob(f"*/{check}/{check}.metadata.json")
    return load_check_metadata(str(path))


def f(check, status, detail, uid, name, region="us-east-1"):
    return Finding(
        auth_method="sts:assumerole",
        timestamp=WHEN,
        account_uid=ACCOUNT,
        account_name="lab-account",
        metadata=meta(check),
        uid=f"prowler-aws-{check}-{ACCOUNT}-{region}-{name}",
        status=status,
        status_extended=detail,
        resource_uid=uid,
        resource_name=name,
        resource_details="",
        region=region,
        prowler_version="5.45.0",
        partition="aws",
    )


u = lambda n: f"arn:aws:iam::{ACCOUNT}:user/{n}"  # noqa: E731
b = lambda n: f"arn:aws:s3:::{n}"  # noqa: E731

findings = [
    # 1 MFA: root without MFA; alice console without MFA; bob fine
    f("iam_root_mfa_enabled", "FAIL", "MFA is not enabled for root account.", ROOT, "<root_account>"),
    f(
        "iam_root_hardware_mfa_enabled",
        "FAIL",
        "Root account has a virtual MFA instead of a hardware MFA device enabled.",
        ROOT,
        "<root_account>",
    ),
    f(
        "iam_user_mfa_enabled_console_access",
        "FAIL",
        "User alice.test has Console Password enabled but MFA disabled.",
        u("alice.test"),
        "alice.test",
    ),
    f(
        "iam_user_mfa_enabled_console_access",
        "PASS",
        "User bob.admin has Console Password enabled and MFA enabled.",
        u("bob.admin"),
        "bob.admin",
    ),
    # 2 Admin
    f(
        "iam_no_root_access_key",
        "PASS",
        "User <root_account> does not have access keys.",
        ROOT,
        "<root_account>",
    ),
    f(
        "iam_avoid_root_usage",
        "PASS",
        "Root user in the account was last accessed 12 days ago.",
        ROOT,
        "<root_account>",
    ),
    f(
        "iam_user_administrator_access_policy",
        "FAIL",
        "IAM User bob.admin has AdministratorAccess policy attached.",
        u("bob.admin"),
        "bob.admin",
    ),
    f(
        "iam_user_administrator_access_policy",
        "PASS",
        "IAM User alice.test does not have AdministratorAccess policy.",
        u("alice.test"),
        "alice.test",
    ),
    f(
        "iam_customer_attached_policy_no_administrative_privileges",
        "FAIL",
        "Custom Policy arn:aws:iam::111122223333:policy/everything-policy is attached and allows '*:*' administrative privileges.",
        f"arn:aws:iam::{ACCOUNT}:policy/everything-policy",
        "everything-policy",
    ),
    # 3 Stale
    f(
        "iam_user_console_access_unused",
        "PASS",
        "User alice.test has logged into the console in the past 45 days.",
        u("alice.test"),
        "alice.test",
    ),
    f(
        "iam_user_accesskey_unused",
        "FAIL",
        "User carol.svc has not used access key 1 in the last 45 days (90 days).",
        u("carol.svc"),
        "carol.svc",
    ),
    f(
        "iam_rotate_access_key_90_days",
        "PASS",
        "User carol.svc does not have access keys older than 90 days.",
        u("carol.svc"),
        "carol.svc",
    ),
    # 4 Roles
    f(
        "iam_role_administratoraccess_policy",
        "PASS",
        "IAM Role icp-assessment does not have AdministratorAccess policy.",
        f"arn:aws:iam::{ACCOUNT}:role/icp-assessment",
        "icp-assessment",
    ),
    # 5 Storage: one public bucket; account-level block off
    f(
        "s3_bucket_public_access",
        "FAIL",
        "S3 Bucket icp-test-public has public access due to bucket policy.",
        b("icp-test-public"),
        "icp-test-public",
    ),
    f(
        "s3_bucket_public_access",
        "PASS",
        "S3 Bucket icp-test-private is not public.",
        b("icp-test-private"),
        "icp-test-private",
    ),
    f(
        "s3_bucket_policy_public_write_access",
        "PASS",
        "S3 Bucket icp-test-public does not allow public write access in the bucket policy.",
        b("icp-test-public"),
        "icp-test-public",
    ),
    f(
        "s3_bucket_public_write_acl",
        "PASS",
        "S3 Bucket icp-test-public is not publicly writable.",
        b("icp-test-public"),
        "icp-test-public",
    ),
    f(
        "s3_bucket_public_list_acl",
        "PASS",
        "S3 Bucket icp-test-public is not publicly listable.",
        b("icp-test-public"),
        "icp-test-public",
    ),
    f(
        "s3_account_level_public_access_blocks",
        "FAIL",
        f"Block Public Access is not configured for the account {ACCOUNT}.",
        f"arn:aws:s3:{'us-east-1'}:{ACCOUNT}:account",
        ACCOUNT,
    ),
    # 7 shared with another account
    f(
        "s3_bucket_cross_account_access",
        "FAIL",
        "S3 Bucket icp-test-private has a bucket policy allowing cross account access.",
        b("icp-test-private"),
        "icp-test-private",
    ),
    # 6 Logging: nothing in two regions
    f(
        "cloudtrail_multi_region_enabled",
        "FAIL",
        "No CloudTrail trails enabled with logging were found.",
        f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail",
        ACCOUNT,
        "us-east-1",
    ),
    f(
        "cloudtrail_multi_region_enabled",
        "FAIL",
        "No CloudTrail trails enabled with logging were found.",
        f"arn:aws:cloudtrail:us-west-2:{ACCOUNT}:trail",
        ACCOUNT,
        "us-west-2",
    ),
    # 7 Access analyzer off in two regions
    f(
        "accessanalyzer_enabled",
        "FAIL",
        f"IAM Access Analyzer in account {ACCOUNT} is not enabled.",
        f"arn:aws:accessanalyzer:us-east-1:{ACCOUNT}:analyzer",
        "analyzer/unknown",
        "us-east-1",
    ),
    f(
        "accessanalyzer_enabled",
        "FAIL",
        f"IAM Access Analyzer in account {ACCOUNT} is not enabled.",
        f"arn:aws:accessanalyzer:us-west-2:{ACCOUNT}:analyzer",
        "analyzer/unknown",
        "us-west-2",
    ),
    # A check this tool does not map: must be dropped on import.
    f(
        "iam_password_policy_minimum_length_14",
        "FAIL",
        "IAM password policy does not require minimum length of 14 characters.",
        f"arn:aws:iam:us-east-1:{ACCOUNT}:password-policy",
        "password-policy",
    ),
]

out = OCSF(findings=findings, file_path=None)
buf = io.StringIO()
out._file_descriptor = buf
out.close_file = True
# keep the buffer readable after the writer "closes" it
buf.close = lambda: None
out.batch_write_data_to_file()
Path(sys.argv[1]).write_text(buf.getvalue(), encoding="utf-8")
print("wrote", len(findings), "findings")
