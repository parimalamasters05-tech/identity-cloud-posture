"""AWS snapshot -> normalized tenant view.

AWS is read by Prowler; the snapshot holds Prowler's results for the checks
this tool maps (`config/prowler_check_map.yaml`), already cut down to what a
finding needs. There is no directory of people to normalize: an AWS finding
names resources (a user, a role, a bucket), so the tenant view is thin and the
rules in `icp.rules.aws` read the results directly.
"""

from __future__ import annotations

from typing import Any

from icp.models.enums import CheckFamily, Platform
from icp.models.snapshot import Snapshot
from icp.normalizers.base import CoverageGap, NormalizedTenant
from icp.risk.prowler_map import load as load_map


def results(tenant: NormalizedTenant) -> list[dict[str, Any]]:
    """Prowler's per-resource results, as the importer stored them."""
    return list((tenant.snapshot.artifact("aws.prowler") or {}).get("results", []))


def _refused_regions(snapshot: Snapshot, rows: list[dict[str, Any]]) -> list[CoverageGap]:
    """A per-region check AWS refused in some regions: those regions are left
    out of its results (see icp.rules.aws), and the report says which."""
    denied = snapshot.artifacts.get("aws.denied")
    if not isinstance(denied, dict):
        return []
    gaps = []
    for rule in load_map().rules:
        refused = [a for a in rule.needs if a in denied]
        regions = sorted({r for a in refused for r in denied[a].get("regions", [])})
        checked = sorted({r["region"] for r in rows if r["check_id"] in rule.checks} - set(regions))
        if rule.collapse != "region" or not regions or not checked:
            continue  # all or nothing: the rule itself is "not assessed"
        by_policy = any(denied[a].get("by_organization_policy") for a in refused)
        gaps.append(
            CoverageGap(
                key=f"aws-refused-{rule.rule_id.lower()}",
                families=(rule.family,),
                reason=(
                    f"AWS refused to list what this check needs ({', '.join(refused)}) in "
                    f"{len(regions)} region{'s' if len(regions) != 1 else ''} ({', '.join(regions)})"
                    + (
                        ", because of a policy set by the organization that manages this account"
                        if by_policy
                        else ""
                    )
                    + f". Those regions were not checked and are left out; the result covers "
                    f"{', '.join(checked)} only."
                ),
            )
        )
    return gaps


#: Always true of a Prowler run: its admin-role check leaves out roles that AWS
#: services use (seen live: a Lambda role with AdministratorAccess was not
#: reported). Recorded as partial coverage, so the family is never shown as
#: "no issues found" for every role.
_SERVICE_ROLES_UNCHECKED = CoverageGap(
    key="aws-service-roles-unchecked",
    families=(CheckFamily.SERVICE_ACCOUNT_PRIVILEGE,),
    reason=(
        "Only roles that people or other AWS accounts can switch into were checked. Roles that "
        "AWS services use (for example a Lambda function's or a server's role) were not checked "
        "for full administrative rights: Prowler leaves them out."
    ),
)


def normalize(snapshot: Snapshot) -> NormalizedTenant:
    account = snapshot.artifact("aws.account") or {}
    prowler = snapshot.artifact("aws.prowler") or {}
    account_id = str(account.get("account_id") or snapshot.tenant_id)
    rows = prowler.get("results", [])
    return NormalizedTenant(
        platform=Platform.AWS,
        tenant_id=snapshot.tenant_id,
        snapshot=snapshot,
        # The alias is the only name an AWS account has; many have none.
        organization_name=account.get("alias") or None,
        primary_domain=f"AWS account {account_id}",
        coverage_gaps=[*_refused_regions(snapshot, rows), _SERVICE_ROLES_UNCHECKED],
        coverage={
            "account_id": account_id,
            "prowler_version": prowler.get("prowler_version"),
            "checks_run": sorted({r["check_id"] for r in rows}),
            "results_total": len(rows),
            "results_failed": sum(1 for r in rows if r.get("status") == "FAIL"),
            "degraded_collectors": list(snapshot.degraded_collectors()),
        },
    )
