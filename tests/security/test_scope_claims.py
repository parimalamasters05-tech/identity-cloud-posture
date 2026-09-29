"""What we tell the client about our access must be exactly true.

A reviewer caught the report saying "restricted to read-only scopes" directly
above a scope list containing admin.directory.user.security, which is not
read-only. The same sentence was in the authorization letter the client signs.
What is true, and enforced, is that the tool only *reads*; these tests pin the
wording to that, and pin the letter's scope list to the code's.
"""

from __future__ import annotations

import re

import pytest
from tests.conftest import REPO_ROOT

from icp.reporting.renderer import ReportRenderer
from icp.security.scopes import (
    GOOGLE_READONLY_SCOPES,
    SCOPE_CAVEATS,
    optional_scopes,
    sorted_scopes,
    write_capable,
)

pytestmark = pytest.mark.security

USER_SECURITY = "https://www.googleapis.com/auth/admin.directory.user.security"

#: Phrases that claim every scope is read-only.
FALSE_CLAIMS = (
    r"restricted to (the )?read-only scopes",
    r"all validated read-only",
    r"access that can only read",
    r"read-only allowlist",
)


def test_every_non_readonly_scope_on_the_allowlist_is_explained():
    unexplained = [
        s for s in GOOGLE_READONLY_SCOPES if not s.endswith(".readonly") and s not in SCOPE_CAVEATS
    ]
    assert unexplained == []


def test_user_security_is_flagged_as_not_read_only():
    assert [s for s, _ in write_capable([*sorted_scopes(), *optional_scopes()])] == [USER_SECURITY]


def _report(tenant, result, scopes: tuple[str, ...]) -> str:
    tenant.snapshot = tenant.snapshot.model_copy(update={"scopes_used": scopes})
    renderer = ReportRenderer()
    context = renderer.build_context(tenant, result, client_name="X", assessor="Y")
    return re.sub(r"\s+", " ", renderer.env.get_template("report.html").render(**context))


@pytest.mark.parametrize("scopes", ["live", "fixture"])
def test_the_report_names_the_exception_instead_of_claiming_read_only(tenant, result, scopes):
    """Live: the scopes a real run records. Fixture: none recorded -- the demo a
    prospect reads must still describe what a real run requests."""
    from dataclasses import replace

    used = (*sorted_scopes(), *optional_scopes()) if scopes == "live" else ()
    html = _report(replace(tenant), result, used)

    for claim in FALSE_CLAIMS:
        assert not re.search(claim, html, re.IGNORECASE), claim
    assert "All but one are read-only scopes" in html
    assert re.search(r"Not a read-only scope:\s*</strong>\s*<span[^>]*>" + re.escape(USER_SECURITY), html)
    assert "could in principle remove" in html  # the cover, in plain words


def test_a_run_without_the_exception_says_all_are_read_only(tenant, result):
    from dataclasses import replace

    html = _report(
        replace(tenant), result, ("https://www.googleapis.com/auth/admin.directory.user.readonly",)
    )
    assert "All are read-only scopes" in html
    assert "Not a read-only scope" not in html


def test_no_scope_that_can_read_file_or_mail_content_is_requestable():
    """drive.readonly was replaced by drive.metadata.readonly after a side-by-side
    comparison on the dev tenant returned identical results. The public-files
    check reads names and sharing settings; nothing here needs content."""
    from icp.security.scopes import ScopeViolation, assert_read_only

    for content_scope in (
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/gmail.readonly",
    ):
        assert content_scope not in GOOGLE_READONLY_SCOPES
        with pytest.raises(ScopeViolation):
            assert_read_only([content_scope])


def test_the_authorization_letter_matches_the_code():
    letter = (REPO_ROOT / "docs" / "authorization-letter.md").read_text("utf-8")
    for claim in FALSE_CLAIMS:
        assert not re.search(claim, letter, re.IGNORECASE), claim
    # Schedule A must list every scope the tool can request -- a client cannot
    # authorize access the letter does not name.
    missing = [s for s in GOOGLE_READONLY_SCOPES if s not in letter]
    assert missing == []
    assert "the one scope that is not" in letter
