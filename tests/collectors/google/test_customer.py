"""The organization profile: the cover's name, and nothing else from the record."""

from __future__ import annotations

from pathlib import Path

import pytest

from icp.collectors.base import CollectorError
from icp.collectors.google.customer import CustomerProfileCollector, project
from icp.security.scopes import assert_read_only, optional_scopes, sorted_scopes

SCOPE = "https://www.googleapis.com/auth/admin.directory.customer.readonly"

#: The shape of a real `customers.get` response.
RECORD = {
    "kind": "admin#directory#customer",
    "id": "C0abc123",
    "customerDomain": "riverside.example",
    "alternateEmail": "founder@gmail.example",
    "phoneNumber": "+44 20 7946 0000",
    "language": "en",
    "customerCreationTime": "2019-03-01T10:00:00.000Z",
    "postalAddress": {
        "organizationName": "Riverside Community Trust ",
        "contactName": "Jo Kelly",
        "addressLine1": "1 High Street",
        "locality": "Riverside",
        "postalCode": "RV1 1AA",
        "countryCode": "GB",
    },
}


def test_keeps_the_name_and_drops_every_contact_detail():
    kept = project(RECORD)
    assert kept == {
        "organization_name": "Riverside Community Trust",
        "customer_domain": "riverside.example",
        "created": "2019-03-01T10:00:00.000Z",
        "language": "en",
    }
    blob = str(kept)
    for detail in ("Jo Kelly", "High Street", "RV1", "+44", "gmail"):
        assert detail not in blob


def test_an_unnamed_profile_projects_to_an_empty_name():
    assert project({"customerDomain": "x.example"})["organization_name"] == ""


def test_the_scope_is_read_only_and_optional():
    """Optional: a client who has not delegated it loses the name, not the assessment."""
    assert_read_only([SCOPE])
    assert SCOPE in optional_scopes()
    assert SCOPE not in sorted_scopes()


def test_the_write_scope_is_refused():
    from icp.security.scopes import ScopeViolation

    with pytest.raises(ScopeViolation):
        assert_read_only(["https://www.googleapis.com/auth/admin.directory.customer"])


class _Refused:
    settings = type("S", (), {"customer_id": "my_customer"})()

    def service(self, *args, **kwargs):
        raise Exception("('unauthorized_client: Client is unauthorized', {})")


def test_undelegated_scope_is_a_named_refusal_not_a_crash():
    with pytest.raises(CollectorError) as caught:
        CustomerProfileCollector().collect(_Refused())
    assert caught.value.refused_scopes == (SCOPE,)
    assert "primary domain instead" in str(caught.value)


def test_an_organization_named_after_its_domain_keeps_the_domain_alias(snapshot, tmp_path: Path):
    """The dev tenant's profile name is its domain. Freezing once turned the
    domain itself into "Test Organization" everywhere."""
    from icp.collectors.google import load_fixture_snapshot
    from icp.normalizers.google import normalize
    from icp.storage.freeze import freeze

    customer = {**snapshot.artifacts["google.customer"], "organization_name": "dev-icp.example"}
    changed = snapshot.model_copy(update={"artifacts": {**snapshot.artifacts, "google.customer": customer}})
    freeze(changed, tmp_path)

    tenant = normalize(load_fixture_snapshot(tmp_path))
    assert tenant.primary_domain == "tenant.example"
    assert tenant.organization_name == "tenant.example"


def test_the_name_is_pseudonymized_when_frozen(snapshot, tmp_path: Path):
    from icp.storage.freeze import freeze

    freeze(snapshot, tmp_path)
    blob = (tmp_path / "google__customer.json").read_text("utf-8")
    assert "Riverside Community Trust" not in blob
    assert "Test Organization" in blob
