"""Whose environment a snapshot is of, and whether that is this engagement's.

Snapshot file names carry a label (m365, aws, the Google tenant label), not
the client: a working copy reused for a second client without changing the
labels would let `report --latest` pick up the first client's snapshot. So
every snapshot a report uses is checked against the identifiers in this
engagement's settings, taken from what the client's own platform returned:

    Google Workspace  primary domain   ICP_GOOGLE_PRIMARY_DOMAIN
    Microsoft 365     tenant ID        ICP_M365_TENANT_ID (its ID, or a verified domain)
    AWS               account ID       the account in ICP_AWS_ROLE_ARN
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from icp.models.enums import Platform
from icp.models.snapshot import Snapshot

_ROLE_ARN_ACCOUNT = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):role/")


@dataclass(frozen=True)
class IdentityCheck:
    found: str  # what the snapshot says, "" if it holds no identifier
    expected: str  # what the settings say, "" if not configured
    setting: str  # the setting the expectation comes from
    matches: bool


def configured(platform: Platform) -> bool:
    """Whether this engagement's settings set the platform up for collection."""
    if platform == Platform.MICROSOFT_365:
        return bool(_env("ICP_M365_TENANT_ID"))
    if platform == Platform.AWS:
        return bool(_env("ICP_AWS_ROLE_ARN"))
    return bool(_env("ICP_TENANT_ID"))


def check(snapshot: Snapshot) -> IdentityCheck:
    if snapshot.platform == Platform.MICROSOFT_365:
        org = snapshot.artifacts.get("m365.organization") or {}
        names = {str(org.get("id") or "")} | {str(d.get("name") or "") for d in org.get("domains", [])}
        names = {n.lower() for n in names if n}
        expected = _env("ICP_M365_TENANT_ID")
        return IdentityCheck(
            found=f"tenant {org.get('id')}" if org.get("id") else "",
            expected=expected,
            setting="ICP_M365_TENANT_ID",
            matches=bool(expected) and expected.lower() in names,
        )
    if snapshot.platform == Platform.AWS:
        account = str((snapshot.artifacts.get("aws.account") or {}).get("account_id") or "")
        arn = _env("ICP_AWS_ROLE_ARN")
        match = _ROLE_ARN_ACCOUNT.match(arn)
        expected = match.group(1) if match else ""
        return IdentityCheck(
            found=f"account {account}" if account else "",
            expected=expected,
            setting="ICP_AWS_ROLE_ARN",
            matches=bool(expected) and account == expected,
        )
    domain = _google_domain(snapshot)
    expected = _env("ICP_GOOGLE_PRIMARY_DOMAIN").lower()
    return IdentityCheck(
        found=f"domain {domain}" if domain else "",
        expected=expected,
        setting="ICP_GOOGLE_PRIMARY_DOMAIN",
        matches=bool(expected) and domain == expected,
    )


def _google_domain(snapshot: Snapshot) -> str:
    # The same sources, in the same order, as the Google normalizer's cover domain.
    domains = (snapshot.artifacts.get("google.drive_settings") or {}).get("domains", []) or []
    primary = next((d.get("domainName") for d in domains if d.get("isPrimary")), None)
    customer = snapshot.artifacts.get("google.customer")
    if not primary and isinstance(customer, dict):
        primary = customer.get("customer_domain")
    return str(primary or "").lower()


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()
