"""The cover is one page, even when several areas could not be read.

Found in the dev-tenant PDF: the "Incomplete coverage" box pushed the
disclaimer onto page 2, which was otherwise blank. Needs WeasyPrint's native
libraries (present in the Docker image); skipped where they are missing.
"""

from __future__ import annotations

import pytest

from icp.models.enums import Assessability
from icp.models.snapshot import CollectionError
from icp.normalizers.google import normalize
from icp.reporting.renderer import ReportRenderer
from icp.rules import assess

try:  # the import itself fails with OSError when the native libraries are absent
    import weasyprint
except (ImportError, OSError) as exc:  # pragma: no cover - environment-dependent
    pytest.skip(f"WeasyPrint unavailable here: {exc}", allow_module_level=True)


def _page_text(page) -> str:
    out: list[str] = []

    def walk(box) -> None:
        if getattr(box, "text", None):
            out.append(box.text)
        for child in getattr(box, "children", []) or []:
            walk(child)

    walk(page._page_box)
    return " ".join(out)


def test_cover_fits_one_page_with_four_areas_not_fully_read(snapshot):
    degraded = (
        "google.mfa",
        "google.token_activity",
        "google.workspace_policies",
        "google.audit_readiness",
    )
    errors = tuple(
        CollectionError(collector=c, assessability=Assessability.NOT_ASSESSABLE_PERMISSION, message="test")
        for c in degraded
    )
    artifacts = {k: v for k, v in snapshot.artifacts.items() if k not in degraded}
    tenant = normalize(snapshot.model_copy(update={"errors": errors, "artifacts": artifacts}))
    renderer = ReportRenderer()
    context = renderer.build_context(
        tenant, assess(tenant), client_name="Riverside Community Trust", assessor="T"
    )
    try:
        document = weasyprint.HTML(
            string=renderer.env.get_template("report.html").render(**context)
        ).render()
    except OSError as exc:  # native libraries missing
        pytest.skip(f"WeasyPrint cannot render here: {exc}")

    first, second = _page_text(document.pages[0]), _page_text(document.pages[1])
    assert "Not fully read" in first
    assert "not legal advice" in first, "the cover overflowed onto page 2"
    assert second.strip().startswith("Executive summary")
