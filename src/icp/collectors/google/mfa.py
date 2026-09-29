"""Second-factor enrollment and method strength.

Enrollment state comes from the Directory API user record. *Method* strength --
whether the second factor is a phishing-resistant security key or an SMS code --
comes from the Reports API, and is not available on every licence tier. When it
is unavailable the check degrades to enrollment-only and says so in the report,
rather than quietly implying every enrolled user is well protected.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from icp.collectors.base import Collector, CollectorClient, CollectorError
from icp.models.enums import Assessability

#: The fields the method-strength check needs, as Google names them. Verified
#: against a live tenant's unfiltered report: the tool used to ask for
#: "accounts:security_key_count", which does not exist -- Google rejected every
#: request, and the old error handling read each rejection as "report not ready
#: yet", so the check never ran for anyone. Passkeys are counted separately
#: from security keys, and both resist phishing.
PARAMETERS = ("accounts:num_security_keys", "accounts:num_passkeys_enrolled")


class MfaCollector(Collector):
    name = "google.mfa"
    required_scopes = ("https://www.googleapis.com/auth/admin.reports.usage.readonly",)

    def collect(self, client: CollectorClient) -> dict[str, Any]:
        service = client.service("admin", "reports_v1")  # type: ignore[attr-defined]

        # The usage report lags; step back until a populated day is found.
        for days_back in (2, 3, 4, 5):
            date = (datetime.now(UTC) - timedelta(days=days_back)).strftime("%Y-%m-%d")
            try:
                reports = client.paginate(
                    service.userUsageReport(),
                    "get",
                    "usageReports",
                    userKey="all",
                    date=date,
                    parameters=",".join(PARAMETERS),
                )
            except Exception as exc:
                status = getattr(getattr(exc, "resp", None), "status", None)
                message = _google_message(exc)
                # Only "that day is not ready" means try an earlier day. Any
                # other rejection is a real error and must say what Google said.
                if status == 404 or (status == 400 and "not yet available" in message.lower()):
                    continue
                if status == 400:
                    raise CollectorError(
                        "Google rejected the request for sign-in method data, so we could not "
                        "check which administrators use a security key or passkey. This is a "
                        f"problem with the assessment tool's request, not your account. Google "
                        f"said: {message}",
                        Assessability.NOT_ASSESSABLE_ERROR,
                        status,
                    ) from exc
                raise
            if reports:
                return {"report_date": date, "entries": _flatten(reports)}

        raise CollectorError(
            "Google had not produced its daily report of which sign-in methods each person uses "
            "in any of the last five days (on a new or very small account this can take several "
            "days), so we could not check which administrators use a security key or passkey. "
            "Whether each account has two-step verification at all was still checked.",
            Assessability.NOT_ASSESSABLE_LICENSE,
        )


def _google_message(exc: Exception) -> str:
    """Google's own error message, from the response body when there is one."""
    import json

    try:
        return str(json.loads(exc.content.decode("utf-8"))["error"]["message"])  # type: ignore[attr-defined]
    except Exception:
        return str(exc)


def _flatten(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse the report's parameter list into a flat dict per user."""
    out = []
    for report in reports:
        entity = report.get("entity", {})
        row: dict[str, Any] = {
            "profile_id": entity.get("profileId"),
            "email": entity.get("userEmail"),
        }
        for param in report.get("parameters", []) or []:
            name = str(param.get("name", "")).split(":")[-1]
            value = (
                param.get("boolValue")
                if "boolValue" in param
                else param.get("intValue", param.get("stringValue"))
            )
            row[name] = value
        out.append(row)
    return out
