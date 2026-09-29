"""Pre-flight checks.

The point of preflight is that a partial delegation grant produces an actionable
sentence rather than a stack trace. These tests assert that property, since it is
the only part of the tool most clients' IT contacts will ever see fail.
"""

from __future__ import annotations

import pytest

from icp.config import Settings
from icp.preflight import PROBES, Probe, ProbeResult, check_configuration, explain

pytestmark = pytest.mark.security


class Resp:
    def __init__(self, status: int) -> None:
        self.status = status


class ApiError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.resp = Resp(status)


def probe(required: bool = True) -> Probe:
    return Probe("Reports: audit", "https://example/auth/reports", "logging readiness", required)


# -- error explanations --------------------------------------------------------


def test_permission_denied_names_the_exact_scope_to_grant():
    """The single most common first-run failure, and the whole point of this module."""
    message = explain(ApiError(403), probe(), 403)
    assert "https://example/auth/reports" in message
    assert "domain-wide delegation" in message


def test_not_found_is_explained_as_a_licence_tier_not_a_defect():
    """A 403 is the client's setup; a 404 is usually their licence. Different fixes."""
    message = explain(ApiError(404), probe(), 404)
    assert "licence" in message.lower()
    assert "coverage notes" in message
    assert "not as passes" in message


def test_bad_request_points_at_the_two_settings_that_cause_it():
    message = explain(ApiError(400), probe(), 400)
    assert "ICP_GOOGLE_CUSTOMER_ID" in message
    assert "ICP_GOOGLE_ADMIN_SUBJECT" in message


def test_unrecognized_errors_are_surfaced_verbatim():
    """Never swallow an error we did not anticipate."""
    assert "ValueError" in explain(ValueError("something odd"), probe(), None)


# -- required vs optional ------------------------------------------------------


def test_a_required_surface_failing_is_a_hard_failure():
    assert ProbeResult(probe(required=True), ok=False).status == "FAIL"


def test_an_optional_surface_failing_only_degrades():
    """A missing licence must not block an otherwise useful assessment."""
    assert ProbeResult(probe(required=False), ok=False).status == "DEGRADED"


def test_the_three_required_surfaces_are_the_right_three():
    """Users, roles and OAuth tokens. Without any of these the report is not worth selling.

    Everything else degrades to a coverage note. Drive in particular is optional
    on purpose: Drive access under domain-wide delegation is a harder ask than
    the directory scopes (even as metadata only), and it should not gate an
    engagement.
    """
    required = {p.name for p in PROBES if p.required}
    assert required == {
        "Directory: users",
        "Directory: admin roles",
        "Directory: OAuth tokens",
    }


def test_every_probe_names_the_checks_it_enables():
    """The operator needs to know what a degraded surface costs them."""
    for p in PROBES:
        assert p.families, f"{p.name} does not say what it affects"
        assert p.scope.startswith("https://")


def test_probes_cover_every_allowlisted_scope_except_orgunit():
    """A scope we request but never probe is a silent gap in preflight."""
    from icp.security.scopes import GOOGLE_READONLY_SCOPES

    probed = {p.scope for p in PROBES}
    unprobed = GOOGLE_READONLY_SCOPES - probed
    # orgunit is read as part of the user record, so it has no separate surface.
    assert unprobed == {"https://www.googleapis.com/auth/admin.directory.orgunit.readonly"}


# -- delegation diagnosis -----------------------------------------------------

_REFUSED = "RefreshError: ('unauthorized_client: Client is unauthorized to retrieve access tokens')"


def _settings_with(scopes: tuple[str, ...]):
    from icp.config import Settings

    return Settings(scopes=scopes)


def test_one_missing_scope_is_named_exactly():
    """Found against a real tenant: a newly added scope made Google refuse the
    whole token, and preflight printed the same opaque error nine times."""
    from icp.preflight import check_delegation

    good = "https://www.googleapis.com/auth/admin.directory.user.readonly"
    missing = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
    settings = _settings_with((good, missing))

    def token_error(_settings, scopes):
        return _REFUSED if missing in scopes else None

    results = check_delegation(settings, token_error)
    assert results is not None
    failed = [r for r in results if not r.ok]
    assert [r.probe.scope for r in failed] == [missing]
    assert missing in failed[0].detail


def test_nothing_delegated_points_at_the_client_id():
    from icp.preflight import check_delegation

    settings = _settings_with(("https://www.googleapis.com/auth/admin.directory.user.readonly",))
    results = check_delegation(settings, lambda _s, _scopes: _REFUSED)
    assert results is not None
    assert any("client ID" in r.detail for r in results)


def test_a_granted_scope_set_proceeds_to_the_api_probes():
    from icp.preflight import check_delegation

    settings = _settings_with(("https://www.googleapis.com/auth/admin.directory.user.readonly",))
    assert check_delegation(settings, lambda _s, _scopes: None) is None


# -- offline configuration checks ---------------------------------------------


def test_missing_environment_is_caught_before_any_network_call(monkeypatch):
    for name in ("ICP_TENANT_ID", "ICP_GOOGLE_ADMIN_SUBJECT", "ICP_GOOGLE_PRIMARY_DOMAIN"):
        monkeypatch.delenv(name, raising=False)
    results = check_configuration(Settings.from_env())
    env = next(r for r in results if r.probe.name == "Environment variables")
    assert not env.ok
    assert "ICP_TENANT_ID" in env.detail


def test_a_complete_configuration_passes(monkeypatch):
    monkeypatch.setenv("ICP_TENANT_ID", "dev")
    monkeypatch.setenv("ICP_GOOGLE_ADMIN_SUBJECT", "icp-assessment@dev.example")
    monkeypatch.setenv("ICP_GOOGLE_PRIMARY_DOMAIN", "dev.example")
    monkeypatch.delenv("ICP_GOOGLE_KEY_FILE", raising=False)
    assert all(r.ok for r in check_configuration(Settings.from_env()))


def test_a_world_readable_key_file_fails_preflight(monkeypatch, tmp_path):
    """Caught here rather than by the client's security team later."""
    key = tmp_path / "sa.json"
    key.write_text("{}")
    key.chmod(0o644)

    monkeypatch.setenv("ICP_TENANT_ID", "dev")
    monkeypatch.setenv("ICP_GOOGLE_ADMIN_SUBJECT", "a@dev.example")
    monkeypatch.setenv("ICP_GOOGLE_PRIMARY_DOMAIN", "dev.example")
    monkeypatch.setenv("ICP_GOOGLE_KEY_FILE", str(key))

    result = next(r for r in check_configuration(Settings.from_env()) if r.probe.name == "Credential file")
    assert not result.ok
    assert "0644" in result.detail


def test_a_missing_key_file_is_reported_by_path(monkeypatch, tmp_path):
    monkeypatch.setenv("ICP_TENANT_ID", "dev")
    monkeypatch.setenv("ICP_GOOGLE_ADMIN_SUBJECT", "a@dev.example")
    monkeypatch.setenv("ICP_GOOGLE_PRIMARY_DOMAIN", "dev.example")
    monkeypatch.setenv("ICP_GOOGLE_KEY_FILE", str(tmp_path / "absent.json"))

    result = next(r for r in check_configuration(Settings.from_env()) if r.probe.name == "Credential file")
    assert not result.ok
    assert "not found" in result.detail


@pytest.mark.security
def test_every_probe_is_a_read():
    """Preflight must not become a way to smuggle a write past the guard."""
    import inspect

    from icp import preflight

    source = inspect.getsource(preflight)
    for forbidden in (".insert(", ".update(", ".patch(", ".delete(", ".create("):
        assert forbidden not in source, f"preflight contains {forbidden}"


# -- platform-specific permission checking -------------------------------------


@pytest.mark.skipif(__import__("os").name != "posix", reason="POSIX permissions only")
def test_a_filesystem_that_cannot_enforce_modes_warns_instead_of_blocking(tmp_path, monkeypatch):
    """Docker Desktop on Windows reports every bind-mounted file as 0777.

    NTFS has no POSIX mode bits, so `chmod 600` provably does nothing there.
    Demanding it would make the tool unusable on Windows and would teach the
    operator to ignore a security message -- worse than not having the check.
    """
    from icp.security import credentials

    key = tmp_path / "sa.json"
    key.write_text("{}")
    key.chmod(0o644)

    monkeypatch.setattr(credentials, "_is_foreign_mount", lambda _p: True)
    credentials._check_file_permissions(key)  # warns, does not raise


@pytest.mark.skipif(__import__("os").name != "posix", reason="POSIX permissions only")
def test_a_real_posix_filesystem_still_blocks_a_leaky_key(tmp_path):
    """The control must keep working where it can actually mean something."""
    from icp.security.credentials import CredentialError, _check_file_permissions

    key = tmp_path / "sa.json"
    key.write_text("{}")
    key.chmod(0o644)

    with pytest.raises(CredentialError, match="0644"):
        _check_file_permissions(key)


@pytest.mark.skipif(__import__("os").name != "posix", reason="POSIX permissions only")
def test_foreign_mount_detection_is_false_on_a_normal_filesystem(tmp_path):
    """Detected by whether a chmod sticks, not by guessing at the platform."""
    from icp.security.credentials import _is_foreign_mount

    key = tmp_path / "sa.json"
    key.write_text("{}")
    key.chmod(0o644)

    assert _is_foreign_mount(key) is False
    # And the probe must leave the file as it found it.
    import stat as _stat

    assert _stat.S_IMODE(key.stat().st_mode) == 0o644


def test_an_unenabled_api_is_not_reported_as_a_missing_scope():
    """Google returns 403 for two unrelated problems.

    `accessNotConfigured` means the API is not enabled on the GCP project.
    Telling the operator to add a scope they already have costs them an hour.
    """
    error = ApiError(403)
    error.args = ("accessNotConfigured: Google Drive API has not been used in project",)
    message = explain(error, probe(), 403)

    assert "not enabled" in message
    assert "APIs & Services" in message
    assert "not a scope problem" in message


def test_a_genuine_delegation_gap_still_names_the_scope():
    message = explain(ApiError(403), probe(), 403)
    assert "domain-wide delegation" in message
    assert "https://example/auth/reports" in message
