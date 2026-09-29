"""Workspace settings via the Cloud Identity Policy API."""

from __future__ import annotations

import pytest

from icp.collectors.base import CollectorError, to_collection_error
from icp.collectors.google.policies import WorkspacePoliciesCollector
from icp.models.enums import Assessability
from icp.models.snapshot import Snapshot
from icp.normalizers.google import normalize


class _FakeService:
    def policies(self) -> str:
        return "policies-resource"


class _FakeClient:
    def __init__(self, policies=None, error: Exception | None = None) -> None:
        self._policies = policies or []
        self._error = error

    def service(self, api: str, version: str, *, optional_scopes: tuple[str, ...] = ()) -> _FakeService:
        assert (api, version) == ("cloudidentity", "v1")
        assert optional_scopes == WorkspacePoliciesCollector.required_scopes, "must use its own token"
        return _FakeService()

    def paginate(self, resource, method, key, **kwargs):
        if self._error:
            raise self._error
        assert (resource, method, key) == ("policies-resource", "list", "policies")
        return self._policies

    def call(self, resource, method, **kwargs):  # pragma: no cover - unused
        raise AssertionError


def _policy(setting_type: str, value: dict, org_unit: str = "orgUnits/root", group: str = "") -> dict:
    return {
        "name": f"policies/{setting_type}-{org_unit}",
        "type": "ADMIN",
        "policyQuery": {"orgUnit": org_unit, "group": group, "sortOrder": 1},
        "setting": {"type": f"settings/{setting_type}", "value": value},
    }


def test_only_the_needed_settings_reach_the_snapshot():
    """Data minimization: the API returns every setting; we keep four types."""
    payload = WorkspacePoliciesCollector().collect(
        _FakeClient(
            [
                _policy("drive_and_docs.external_sharing", {"externalSharingMode": "ALLOWED"}),
                _policy("gmail.mail_delegation", {"enableMailDelegation": True}),
                _policy("security.two_step_verification_enrollment", {"allowEnrollment": True}),
            ]
        )
    )
    assert payload["setting_types_found"] == [
        "drive_and_docs.external_sharing",
        "security.two_step_verification_enrollment",
    ]
    assert all(not p["setting_type"].startswith("settings/") for p in payload["policies"])
    assert "gmail" not in str(payload)


def test_api_not_enabled_is_named_as_such_not_as_a_scope_problem():
    """Google returns 403 for both; telling the operator to fix the wrong one costs an hour."""

    class _Disabled(Exception):
        resp = type("R", (), {"status": 403})()

        def __str__(self) -> str:
            return "Cloud Identity API has not been used in project 123 before or it is disabled"

    with pytest.raises(CollectorError) as caught:
        WorkspacePoliciesCollector().collect(_FakeClient(error=_Disabled()))
    error = to_collection_error("google.workspace_policies", caught.value)
    assert error.assessability == Assessability.NOT_ASSESSABLE_PERMISSION
    assert "not enabled" in error.message
    assert "APIs & Services" in error.message


def test_an_undelegated_scope_degrades_this_collector_with_the_fix():
    """Found against a real tenant: with the scope in the shared token, one
    missing delegation made Google refuse every call in the run."""

    class _Refused(Exception):
        def __str__(self) -> str:
            return "('unauthorized_client: Client is unauthorized to retrieve access tokens', {})"

    with pytest.raises(CollectorError) as caught:
        WorkspacePoliciesCollector().collect(_FakeClient(error=_Refused()))
    assert "cloud-identity.policies.readonly" in str(caught.value)
    assert "Domain-wide delegation" in str(caught.value)


def test_optional_scopes_never_enter_the_main_token():
    from icp.config import Settings
    from icp.security.scopes import GOOGLE_READONLY_SCOPES

    settings = Settings()
    assert WorkspacePoliciesCollector.required_scopes[0] in settings.optional_scopes
    assert not set(settings.optional_scopes) & set(settings.scopes)
    assert set(settings.optional_scopes) <= GOOGLE_READONLY_SCOPES


# -- normalization -------------------------------------------------------------


def _tenant_with(*policies: dict):
    snapshot = Snapshot(
        snapshot_id="s",
        tenant_id="t",
        platform="google_workspace",
        artifacts={
            "google.workspace_policies": {
                "policies": [
                    {
                        "name": p["name"],
                        "policy_type": "ADMIN",
                        "setting_type": p["setting"]["type"].removeprefix("settings/"),
                        "org_unit": p["policyQuery"]["orgUnit"],
                        "group": p["policyQuery"]["group"],
                        "sort_order": 1,
                        "value": p["setting"]["value"],
                    }
                    for p in policies
                ]
            }
        },
    )
    return normalize(snapshot).policy


SHARING = "drive_and_docs.external_sharing"


@pytest.mark.parametrize(
    "value,allowed,warned",
    [
        ({"externalSharingMode": "ALLOWED", "warnForExternalSharing": False}, True, False),
        ({"externalSharingMode": "ALLOWED", "warnForExternalSharing": True}, True, True),
        ({"externalSharingMode": "DISALLOWED"}, False, True),
        # Allowlisted domains use their own warning field.
        (
            {"externalSharingMode": "ALLOWLISTED_DOMAINS", "warnForSharingOutsideAllowlistedDomains": True},
            True,
            True,
        ),
        # Google's settings reference also spells the fields in snake_case.
        ({"external_sharing_mode": "ALLOWED", "warn_for_external_sharing": False}, True, False),
    ],
)
def test_sharing_policy_is_read_from_the_setting(value, allowed, warned):
    policy = _tenant_with(_policy(SHARING, value))
    assert policy.external_sharing_allowed is allowed
    assert policy.external_sharing_warning_enabled is warned


def test_one_unwarned_unit_is_enough_and_is_named():
    """A locked-down top level does not excuse a sub-unit that shares freely."""
    policy = _tenant_with(
        _policy(SHARING, {"externalSharingMode": "ALLOWED", "warnForExternalSharing": True}),
        _policy(
            SHARING,
            {"externalSharingMode": "ALLOWED", "warnForExternalSharing": False},
            org_unit="orgUnits/contractors",
        ),
    )
    assert policy.external_sharing_warning_enabled is False
    assert [p["org_unit"] for p in policy.raw["drive_sharing"]["unwarned"]] == ["orgUnits/contractors"]


def test_an_absent_warning_field_takes_googles_default_which_is_on():
    """Google documents absent fields as their defaults, and the warning
    defaults to on. Reading "absent" as "off" invents a finding."""
    policy = _tenant_with(_policy(SHARING, {"externalSharingMode": "ALLOWED"}))
    assert policy.external_sharing_warning_enabled is True


def test_no_drive_policy_returned_means_googles_defaults():
    """Found against a real tenant: the API returned only the settings an admin
    had changed (2SV). An untouched Drive setting is at its default: external
    sharing allowed, warning on -- which is a pass, not a gap."""
    policy = _tenant_with(_policy("security.two_step_verification_enrollment", {"allowEnrollment": True}))
    assert policy.external_sharing_allowed is True
    assert policy.external_sharing_warning_enabled is True
    assert policy.raw["drive_sharing"]["source"] == "google default"


def test_policies_never_read_stay_unknown():
    snapshot = Snapshot(snapshot_id="s", tenant_id="t", platform="google_workspace", artifacts={})
    policy = normalize(snapshot).policy
    assert policy.external_sharing_allowed is None
    assert policy.external_sharing_warning_enabled is None
