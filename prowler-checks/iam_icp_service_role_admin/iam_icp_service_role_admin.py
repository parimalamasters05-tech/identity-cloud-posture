"""Roles that AWS services use, checked for full administrative rights.

Prowler's own iam_role_administratoraccess_policy leaves out every role an AWS
service can assume ("service roles cannot be modified by the user"), so a
Lambda function's role holding AdministratorAccess was never reported (seen
live, 14 Oct 2026). This check covers exactly the roles that one skips.

Read-only: it uses only what Prowler's IAM service has already listed (roles,
their trust policies and attached policies) and makes no AWS call itself.
Service-linked roles (path /aws-service-role/) are AWS's own and left out.
"""

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

ADMINISTRATOR_ACCESS = "AdministratorAccess"


class iam_icp_service_role_admin(Check):  # noqa: N801 - Prowler requires the check ID as the class name
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for role in iam_client.roles or []:
            if not role.is_service_role or "/aws-service-role/" in role.arn:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.region = iam_client.region
            admin = [p for p in role.attached_policies if p.get("PolicyName") == ADMINISTRATOR_ACCESS]
            if admin:
                report.status = "FAIL"
                report.status_extended = (
                    f"Service role {role.name} has the AdministratorAccess policy attached."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Service role {role.name} does not have the AdministratorAccess policy attached."
                )
            findings.append(report)
        if not findings:
            # Always one result, so "ran and found no service roles" can be told
            # apart from "this check was not run" (an older scan).
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = iam_client.region
            report.resource_id = "service-roles"
            report.resource_arn = iam_client.audited_account_arn
            report.status = "PASS"
            report.status_extended = "No roles used by AWS services were found."
            findings.append(report)
        return findings
