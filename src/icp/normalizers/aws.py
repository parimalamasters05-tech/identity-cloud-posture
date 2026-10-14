"""AWS snapshot -> normalized tenant view.

AWS is read by Prowler; the snapshot holds Prowler's results for the checks
this tool maps (`config/prowler_check_map.yaml`), already cut down to what a
finding needs. There is no directory of people to normalize: an AWS finding
names resources (a user, a role, a bucket), so the tenant view is thin and the
rules in `icp.rules.aws` read the results directly.
"""

from __future__ import annotations

from typing import Any

from icp.models.enums import Platform
from icp.models.snapshot import Snapshot
from icp.normalizers.base import NormalizedTenant


def results(tenant: NormalizedTenant) -> list[dict[str, Any]]:
    """Prowler's per-resource results, as the importer stored them."""
    return list((tenant.snapshot.artifact("aws.prowler") or {}).get("results", []))


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
        coverage={
            "account_id": account_id,
            "prowler_version": prowler.get("prowler_version"),
            "checks_run": sorted({r["check_id"] for r in rows}),
            "results_total": len(rows),
            "results_failed": sum(1 for r in rows if r.get("status") == "FAIL"),
            "degraded_collectors": list(snapshot.degraded_collectors()),
        },
    )
