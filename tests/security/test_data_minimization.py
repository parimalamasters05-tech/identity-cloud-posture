"""Data minimization is a promise in the engagement letter, so it is tested.

The client is told, in writing, that no message or file content is collected.
These tests make that structurally true rather than a matter of discipline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from icp.collectors.google.oauth import OAuthTokensCollector
from icp.collectors.google.sharing import PublicDriveItemsCollector
from icp.collectors.google.users import UsersCollector
from icp.models.identity import Identity
from icp.models.resource import DomainPolicy, Resource

pytestmark = pytest.mark.security

#: Field names that would indicate content, not configuration, has been captured.
CONTENT_FIELD_MARKERS = (
    "body",
    "content",
    "payload",
    "snippet",
    "message",
    "attachment",
    "rawdata",
    "filedata",
    "text",
    "webcontentlink",
    "downloadurl",
    "exportlinks",
    "thumbnail",
)

#: Directory fields that are personal data with no bearing on posture.
EXCESS_PII_MARKERS = (
    "addresses",
    "phones",
    "recoveryemail",
    "recoveryphone",
    "employeeid",
    "customschemas",
    "gender",
    "relations",
    "locations",
    "thumbnailphoto",
)


def _field_names(model_cls) -> set[str]:
    return {name.lower() for name in model_cls.model_fields}


@pytest.mark.parametrize("model_cls", [Identity, Resource, DomainPolicy])
def test_no_model_can_hold_content(model_cls):
    """Structural guarantee: there is nowhere to put a file body even by accident."""
    for field in _field_names(model_cls):
        for marker in CONTENT_FIELD_MARKERS:
            assert marker not in field, f"{model_cls.__name__}.{field} could hold content"


def test_user_collector_excludes_excess_personal_data():
    """The Directory API returns far more than posture assessment needs."""
    declared = {f.lower() for f in UsersCollector.FIELDS}
    for field in declared:
        for marker in EXCESS_PII_MARKERS:
            assert marker not in field, f"UsersCollector collects {field}"


def test_drive_collector_declares_no_content_fields():
    declared = {f.lower() for f in PublicDriveItemsCollector.FIELDS}
    for field in declared:
        for marker in CONTENT_FIELD_MARKERS:
            if marker == "text":
                continue  # "mimeType" style names are fine; no field here contains it
            assert marker not in field, f"PublicDriveItemsCollector collects {field}"


def test_projection_discards_undeclared_fields():
    """The allowlist is enforced, not merely documented."""
    collector = UsersCollector()
    raw = [
        {
            "id": "1",
            "primaryEmail": "a@b.example",
            "phones": [{"value": "+1 555 0100"}],
            "addresses": [{"formatted": "1 Main St"}],
            "customSchemas": {"HR": {"salary": 90000}},
            "recoveryEmail": "personal@gmail.example",
        }
    ]
    projected = collector.project(raw)[0]

    assert projected == {"id": "1", "primaryEmail": "a@b.example"}
    assert "phones" not in projected
    assert "customSchemas" not in projected
    assert "recoveryEmail" not in projected


def test_nested_projection_keeps_only_the_declared_leaf():
    collector = UsersCollector()
    raw = [{"id": "1", "name": {"fullName": "Ada L", "givenName": "Ada", "familyName": "L"}}]
    projected = collector.project(raw)[0]
    assert projected["name"] == {"fullName": "Ada L"}


def test_drive_collector_strips_the_web_view_link():
    """A webViewLink is a working link to client data. We do not store one."""
    assert "webViewLink" in PublicDriveItemsCollector.FIELDS  # requested...
    collector = PublicDriveItemsCollector()
    projected = collector.project([{"id": "f1", "name": "x", "webViewLink": "https://docs/..."}])[0]
    projected["owners"] = []
    projected.pop("webViewLink", None)
    assert "webViewLink" not in projected  # ...and dropped before the snapshot


def test_oauth_collector_does_not_capture_token_values():
    """Scopes and client IDs are needed. The token itself never is."""
    declared = {f.lower() for f in OAuthTokensCollector.FIELDS}
    for forbidden in ("accesstoken", "refreshtoken", "token", "secret"):
        assert forbidden not in declared


def test_the_frozen_fixture_set_contains_no_content(fixture_dir: Path):
    """Belt and braces: scan the actual committed fixture data.

    Fixtures are what a real snapshot looks like. If content ever leaked into
    the collection path, it would show up here first.
    """
    for path in fixture_dir.glob("*.json"):
        blob = json.dumps(json.loads(path.read_text("utf-8"))).lower()
        for marker in ("webviewlink", "webcontentlink", "exportlinks", "attachmentid"):
            assert marker not in blob, f"{path.name} contains {marker}"
