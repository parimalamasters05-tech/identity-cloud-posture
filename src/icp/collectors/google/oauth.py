"""Third-party OAuth grant enumeration -- the project's differentiator.

Google exposes issued tokens per user, not tenant-wide, so this is one call per
user: the slowest collector by an order of magnitude and the one most likely to
hit rate limits. It is written accordingly -- bounded concurrency, per-user
failure isolation, and no early abort.

A single user's enumeration failing must not lose the other 39 users' grants,
because the aggregate is the finding.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from icp.collectors.base import Collector, CollectorClient, CollectorError
from icp.models.enums import Assessability

logger = logging.getLogger(__name__)

#: Google's per-user token endpoint is not batched. Modest concurrency keeps the
#: run inside the five-minute budget without tripping user-rate limits.
_MAX_WORKERS = 8


class OAuthTokensCollector(Collector):
    name = "google.oauth_tokens"
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.user.security",)

    FIELDS = ("clientId", "displayText", "anonymous", "nativeApp", "scopes", "userKey", "kind")

    def collect(self, client: CollectorClient) -> dict[str, Any]:
        users = getattr(client, "known_users", None) or []
        if not users:
            # An empty grant list here would read downstream as "no apps found",
            # a pass on the report's headline check. No users means not assessed.
            raise CollectorError(
                "No user list was available (the users collector did not return data), so "
                "third-party application grants could not be enumerated.",
                Assessability.NOT_ASSESSABLE_ERROR,
            )

        grants: list[dict[str, Any]] = []
        failed: list[dict[str, str]] = []

        def fetch(user: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]] | None, str | None]:
            user_key = user.get("primaryEmail") or user.get("id")
            try:
                # Resolved inside the worker so each thread gets its own
                # httplib2 transport; a service built on the calling thread and
                # shared here corrupts the heap (glibc abort, no traceback).
                service = client.service("admin", "directory_v1")  # type: ignore[attr-defined]
                response = client.call(service.tokens(), "list", userKey=user_key)
                return user, response.get("items", []) or [], None
            except Exception as exc:
                return user, None, f"{type(exc).__name__}: {exc}"

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(fetch, user) for user in users]
            for future in as_completed(futures):
                user, items, error = future.result()
                if error is not None:
                    failed.append({"user_id": str(user.get("id")), "error": error})
                    continue
                for token in items or []:
                    record = self._project_one(token)
                    record["userKey"] = user.get("primaryEmail")
                    record["userId"] = user.get("id")
                    record["userSuspended"] = bool(user.get("suspended"))
                    record["userArchived"] = bool(user.get("archived"))
                    grants.append(record)

        if failed:
            logger.warning("OAuth enumeration failed for %d of %d users", len(failed), len(users))

        return {
            "grants": grants,
            "failed_users": failed,
            "users_enumerated": len(users) - len(failed),
            "users_total": len(users),
        }
