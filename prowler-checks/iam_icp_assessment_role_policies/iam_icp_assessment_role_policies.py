"""The assessment role's own permissions, read back from AWS.

The report says the scan ran through a role holding only the AWS-managed
SecurityAudit and ViewOnlyAccess policies. Without this check that rested on
how the role was set up; with it, the policies actually attached are read and
compared, so the read-only claim is verified, not assumed.

PASS: the role holds those two policies (or a subset) and nothing else, no
inline policy, and no other attached policy. FAIL: anything more. MANUAL: the
scan did not run through an assumed role, so there is no role to check.

Read-only: it uses only what Prowler's IAM service has already listed and the
role ARN Prowler was started with; it makes no AWS call itself.
"""

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

#: The only policies the assessment role may hold (the brief, section 5).
ALLOWED = {
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
}


def _assumed_role_arn() -> str:
    configuration = getattr(iam_client.provider, "_assumed_role_configuration", None)
    try:
        return str(configuration.info.role_arn.arn) if configuration else ""
    except AttributeError:
        return ""


class iam_icp_assessment_role_policies(Check):  # noqa: N801 - Prowler requires the check ID as the class name
    def execute(self) -> list[Check_Report_AWS]:
        role_arn = _assumed_role_arn()
        role = next((r for r in iam_client.roles or [] if r.arn == role_arn), None) if role_arn else None
        if role is None:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = iam_client.region
            report.resource_id = role_arn.rsplit("/", 1)[-1] if role_arn else "assessment-role"
            report.resource_arn = role_arn or iam_client.audited_account_arn
            report.status = "MANUAL"
            report.status_extended = (
                "The scan did not run through an assumed role that could be read back, so the "
                "assessment role's policies could not be checked."
            )
            return [report]

        report = Check_Report_AWS(metadata=self.metadata(), resource=role)
        report.region = iam_client.region
        attached = sorted(p.get("PolicyArn", "") for p in role.attached_policies)
        extra = [arn for arn in attached if arn not in ALLOWED]
        inline = sorted(role.inline_policies or [])
        if extra or inline:
            report.status = "FAIL"
            report.status_extended = (
                f"Assessment role {role.name} holds more than read-only audit policies: "
                + ", ".join([*(a.rsplit("/", 1)[-1] for a in extra), *(f"inline {n}" for n in inline)])
                + "."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"Assessment role {role.name} holds only "
                + (", ".join(a.rsplit("/", 1)[-1] for a in attached) or "no policies")
                + ", and no inline policy."
            )
        return [report]
