"""The organization's own profile: its name, for the report cover.

Read from Directory API `customers.get("my_customer")`, which is what Admin
console > Account > Account settings > Profile shows. The cover used to take the
name from configuration, and printed "Client" whenever that was missing.

Data minimization: the customer record also carries a postal address, a phone
number, a contact name and an alternate email address. None of it is needed,
so none of it is kept.
"""

from __future__ import annotations

from typing import Any

from icp.collectors.base import Collector, CollectorClient, CollectorError
from icp.models.enums import Assessability


class CustomerProfileCollector(Collector):
    name = "google.customer"
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.customer.readonly",)

    def collect(self, client: CollectorClient) -> dict[str, Any]:
        try:
            service = client.service(  # type: ignore[attr-defined]
                "admin", "directory_v1", optional_scopes=self.required_scopes
            )
            record = client.call(  # type: ignore[attr-defined]
                service.customers(),
                "get",
                customerKey=client.settings.customer_id,  # type: ignore[attr-defined]
            )
        except Exception as exc:
            if "unauthorized_client" in str(exc):
                raise CollectorError(
                    "The organization's name was not read: the scope "
                    f"{self.required_scopes[0]} is not in the service account's domain-wide "
                    "delegation entry, so the report cover shows the primary domain instead. Add "
                    "it in Admin console > Security > API controls > Domain-wide delegation.",
                    Assessability.NOT_ASSESSABLE_PERMISSION,
                    refused_scopes=self.required_scopes,
                ) from exc
            raise
        return project(record)


def project(record: dict[str, Any]) -> dict[str, Any]:
    """Keep the name and the facts about the account; drop contact details."""
    address = record.get("postalAddress") or {}
    return {
        "organization_name": (address.get("organizationName") or "").strip(),
        "customer_domain": record.get("customerDomain") or "",
        "created": record.get("customerCreationTime"),
        "language": record.get("language"),
    }
