"""Workspace admin-console settings, via the Cloud Identity Policy API.

This is where Drive's external-sharing policy and organization-wide 2SV
enforcement actually live. The Directory API does not expose them, which is why
an earlier version of this tool reported the sharing policy without having read
it.

A setting can hold a different value per organizational unit or group, so one
setting type may return several policies. All are kept; the normalizer decides
what the organization-wide answer is.

Data minimization: the API returns every setting the tenant has. Only the
setting types listed in `SETTING_TYPES` are retained in the snapshot.
"""

from __future__ import annotations

from typing import Any

from icp.collectors.base import Collector, CollectorClient, CollectorError
from icp.models.enums import Assessability

#: Setting types retained, without the "settings/" prefix the API may add.
SETTING_TYPES = frozenset(
    {
        "drive_and_docs.external_sharing",
        "drive_and_docs.general_access_default",
        "security.two_step_verification_enforcement",
        "security.two_step_verification_enrollment",
    }
)


def setting_type(raw: str | None) -> str:
    return (raw or "").removeprefix("settings/")


class WorkspacePoliciesCollector(Collector):
    name = "google.workspace_policies"
    required_scopes = ("https://www.googleapis.com/auth/cloud-identity.policies.readonly",)

    def collect(self, client: CollectorClient) -> dict[str, Any]:
        try:
            service = client.service(  # type: ignore[attr-defined]
                "cloudidentity", "v1", optional_scopes=self.required_scopes
            )
            policies = client.paginate(service.policies(), "list", "policies", pageSize=100)
        except Exception as exc:
            if "unauthorized_client" in str(exc):
                raise CollectorError(
                    "Workspace settings (Drive sharing policy) were not read: the scope "
                    f"{self.required_scopes[0]} is not in the service account's domain-wide "
                    "delegation entry. Add it in Admin console > Security > API controls > "
                    "Domain-wide delegation.",
                    Assessability.NOT_ASSESSABLE_PERMISSION,
                    refused_scopes=self.required_scopes,
                ) from exc
            if "accessNotConfigured" in str(exc) or "has not been used in project" in str(exc):
                raise CollectorError(
                    "The Cloud Identity API is not enabled on the GCP project, so Workspace "
                    "settings (Drive sharing policy, 2-step verification enforcement) were not "
                    "read. Enable it under APIs & Services > Library; this is not a scope problem.",
                    Assessability.NOT_ASSESSABLE_PERMISSION,
                    getattr(getattr(exc, "resp", None), "status", None),
                ) from exc
            raise

        kept = [
            _project(p)
            for p in policies
            if setting_type((p.get("setting") or {}).get("type")) in SETTING_TYPES
        ]
        return {
            "policies": sorted(
                kept, key=lambda p: (p["setting_type"], p["org_unit"], p["group"], p["name"])
            ),
            "setting_types_found": sorted({p["setting_type"] for p in kept}),
        }


def _project(policy: dict[str, Any]) -> dict[str, Any]:
    query = policy.get("policyQuery") or {}
    setting = policy.get("setting") or {}
    return {
        "name": policy.get("name", ""),
        "policy_type": policy.get("type"),
        "setting_type": setting_type(setting.get("type")),
        "org_unit": query.get("orgUnit") or "",
        "group": query.get("group") or "",
        "sort_order": query.get("sortOrder"),
        "value": dict(setting.get("value") or {}),
    }
