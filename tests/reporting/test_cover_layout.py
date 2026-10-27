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


def test_a_three_platform_test_environment_cover_fits_one_page(snapshot):
    """Seen live (27 Oct 2026): Google, Microsoft 365 and AWS together, marked as
    a test environment and with areas not fully read, pushed the disclaimer onto
    an otherwise blank page 2."""
    from tests.rules.test_aws_rules import _run as run_aws
    from tests.rules.test_m365_rules import _run as run_m365

    from icp.collectors.microsoft import PERMISSIONS_USED

    # As in the live report: one Google area and one AWS area not fully read.
    def degraded(collector: str) -> CollectionError:
        return CollectionError(
            collector=collector, assessability=Assessability.NOT_ASSESSABLE_PERMISSION, message="test"
        )

    google = normalize(snapshot.model_copy(update={"errors": (degraded("google.public_drive_items"),)}))
    m365_tenant, m365_result, _ = run_m365(scopes_used=PERMISSIONS_USED)
    _, aws_tenant, aws_result, _ = run_aws()
    aws_tenant.snapshot = aws_tenant.snapshot.model_copy(
        update={"errors": (*aws_tenant.snapshot.errors, degraded("aws.accessanalyzer"))}
    )
    renderer = ReportRenderer(test_environment=True)
    context = renderer.build_combined_context(
        [(google, assess(google)), (m365_tenant, m365_result), (aws_tenant, aws_result)],
        client_name="Identity Posture Lab",
        assessor="T",
    )
    # The live report had 22 actions; one page holds about 28 at a writable size.
    assert len(context["tracking_sheet"]) > 22
    context["tracking_sheet"] = context["tracking_sheet"][:22]
    try:
        document = weasyprint.HTML(
            string=renderer.env.get_template("report.html").render(**context)
        ).render()
    except OSError as exc:
        pytest.skip(f"WeasyPrint cannot render here: {exc}")

    first, second = _page_text(document.pages[0]), _page_text(document.pages[1])
    assert "not legal advice" in first, "the cover overflowed onto page 2"
    assert second.strip().startswith("Executive summary")
    # At that size the tracking sheet is one page: the last page starts with its heading.
    assert "Remediation tracking sheet" in _page_text(document.pages[-1])
