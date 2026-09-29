"""The scope allowlist is the pre-authentication control.

It runs before a credential is constructed, so an over-broad scope can never
reach Google's token endpoint.
"""

from __future__ import annotations

import pytest

from icp.security.scopes import (
    GOOGLE_FORBIDDEN_SCOPES,
    GOOGLE_READONLY_SCOPES,
    ScopeViolation,
    assert_read_only,
    sorted_scopes,
)

pytestmark = pytest.mark.security


def test_the_default_scope_set_validates():
    assert_read_only(list(sorted_scopes()))


def test_empty_scope_set_is_rejected():
    """Authenticating with no scopes is a bug, not a safe default."""
    with pytest.raises(ScopeViolation, match="No scopes"):
        assert_read_only([])


@pytest.mark.parametrize("scope", sorted(GOOGLE_FORBIDDEN_SCOPES))
def test_known_write_scopes_are_rejected(scope):
    with pytest.raises(ScopeViolation):
        assert_read_only([scope])


def test_unknown_scope_is_rejected_even_if_it_looks_harmless():
    """Default-deny. A scope nobody has reviewed is not a scope we request."""
    with pytest.raises(ScopeViolation, match="not on the read-only allowlist"):
        assert_read_only(["https://www.googleapis.com/auth/calendar.readonly"])


def test_write_marker_substring_is_caught():
    with pytest.raises(ScopeViolation, match="write marker"):
        assert_read_only(["https://www.googleapis.com/auth/admin.directory.user.write"])


def test_a_single_bad_scope_poisons_an_otherwise_valid_set():
    """Validation is all-or-nothing; there is no partial success."""
    scopes = [*sorted_scopes(), "https://www.googleapis.com/auth/drive"]
    with pytest.raises(ScopeViolation):
        assert_read_only(scopes)


def test_allowlist_and_forbidden_list_do_not_overlap():
    """A scope in both lists would make the outcome depend on check order."""
    assert set() == GOOGLE_READONLY_SCOPES & GOOGLE_FORBIDDEN_SCOPES


def test_every_allowlisted_scope_is_readonly_or_documented():
    """Only one non-`.readonly` scope is permitted, and it is the OAuth-token one.

    Google publishes no read-only variant of `admin.directory.user.security`,
    which is what makes check family 7 possible at all. The transport guard is
    what constrains it. If this test ever fails, someone has added a second
    exception and must justify it here.
    """
    exceptions = {"https://www.googleapis.com/auth/admin.directory.user.security"}
    non_readonly = {s for s in GOOGLE_READONLY_SCOPES if not s.endswith(".readonly")}
    assert non_readonly == exceptions


def test_scope_ordering_is_deterministic():
    """Scopes are recorded verbatim in every snapshot and report."""
    assert sorted_scopes() == sorted_scopes()
    assert list(sorted_scopes()) == sorted(sorted_scopes())
