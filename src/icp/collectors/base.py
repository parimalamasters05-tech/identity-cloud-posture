"""Collector contract.

A collector does exactly one thing: pull raw API responses for one subject area
and hand them back. It performs no analysis, applies no judgement, and never
writes. Everything interesting happens downstream of the snapshot.

Two rules every collector must honour:

  * **Data minimization.** Declare `FIELDS` and project the response down to it.
    We collect configuration and metadata, never content. A collector that
    returns a message body or file content is a policy violation, not a bug.
  * **Graceful degradation.** A permission or licensing failure degrades one
    collector and is recorded as a `CollectionError`. It never aborts the run.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from icp.models.enums import Assessability
from icp.models.snapshot import CollectionError

logger = logging.getLogger(__name__)


class CollectorClient(Protocol):
    """Minimal surface a collector needs. Keeps collectors testable offline."""

    def paginate(self, resource: Any, method: str, key: str, **kwargs: Any) -> list[dict[str, Any]]: ...
    def call(self, resource: Any, method: str, **kwargs: Any) -> dict[str, Any]: ...


class CollectorError(Exception):
    """Raised inside a collector to signal a degraded (not fatal) failure."""

    def __init__(
        self,
        message: str,
        assessability: Assessability,
        http_status: int | None = None,
        refused_scopes: tuple[str, ...] = (),
    ):
        super().__init__(message)
        self.assessability = assessability
        self.http_status = http_status
        #: Scopes Google refused a token for; kept out of the snapshot's granted list.
        self.refused_scopes = refused_scopes


class Collector(ABC):
    """Base class for all collectors."""

    #: Snapshot artifact key. Stable; downstream code indexes on it.
    name: str = ""

    #: Scopes this collector needs. Used to explain permission failures precisely.
    required_scopes: tuple[str, ...] = ()

    #: Allowlist of fields retained from each API object. Empty means "no
    #: projection", which is only acceptable for small, purely-config responses.
    FIELDS: tuple[str, ...] = ()

    @abstractmethod
    def collect(self, client: CollectorClient) -> Any:
        """Return raw (projected) API data for this subject area."""

    # -- helpers available to subclasses ---------------------------------------

    def project(self, items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Reduce each object to `FIELDS`.

        This is the data-minimization control in practice: whatever the API
        returns, only declared fields ever reach the snapshot. Nested paths are
        supported with dots (`name.fullName`).
        """
        if not self.FIELDS:
            return [dict(item) for item in items]
        return [self._project_one(item) for item in items]

    def _project_one(self, item: Mapping[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for field in self.FIELDS:
            if "." in field:
                head, _, tail = field.partition(".")
                nested = item.get(head)
                if isinstance(nested, Mapping) and tail in nested:
                    out.setdefault(head, {})[tail] = nested[tail]
            elif field in item:
                out[field] = item[field]
        return out


def to_collection_error(collector: str, exc: Exception) -> CollectionError:
    """Translate an exception into a recorded, reportable degradation."""
    if isinstance(exc, CollectorError):
        return CollectionError(
            collector=collector,
            assessability=exc.assessability,
            message=str(exc),
            http_status=exc.http_status,
        )

    status = getattr(getattr(exc, "resp", None), "status", None)
    if status in (401, 403):
        assessability = Assessability.NOT_ASSESSABLE_PERMISSION
        message = (
            f"Access denied ({status}). The service account is missing a required scope, "
            "or domain-wide delegation was not granted for it."
        )
    elif status == 404:
        assessability = Assessability.NOT_ASSESSABLE_LICENSE
        message = "Endpoint unavailable (404), typically a licensing tier that does not expose it."
    else:
        assessability = Assessability.NOT_ASSESSABLE_ERROR
        message = f"{type(exc).__name__}: {exc}"

    return CollectionError(
        collector=collector, assessability=assessability, message=message, http_status=status
    )
