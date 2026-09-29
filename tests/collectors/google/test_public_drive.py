"""Public Drive files are found wherever they are owned, not just the admin's.

Found on the dev tenant: a file admin-test3 shared "anyone with the link" was
missing from the report, because the search ran only as admin@ and Drive
returns only what the signed-in account can see.
"""

from __future__ import annotations

import threading

from icp.collectors.google.sharing import PublicDriveItemsCollector

DOMAIN = "org.example"


def _file(fid: str, name: str, owner: str) -> dict:
    return {
        "id": fid,
        "name": name,
        "mimeType": "application/vnd.google-apps.document",
        "shared": True,
        "modifiedTime": "2026-09-01T00:00:00.000Z",
        "owners": [{"emailAddress": f"{owner}@{DOMAIN}"}],
        "webViewLink": "https://docs.example/secret",
    }


#: What each account's own search returns. The admin search also sees a shared drive.
DRIVE = {
    None: [_file("a1", "Admin's public deck", "admin"), _file("sd1", "Shared drive: board", "admin")],
    f"admin@{DOMAIN}": [_file("a1", "Admin's public deck", "admin")],
    f"staff1@{DOMAIN}": [_file("s1", "Staff donor list", "staff1")],
    f"staff2@{DOMAIN}": [],
}


class _Files:
    def __init__(self, subject, log):
        self.subject, self.log = subject, log

    def list(self, **kwargs):
        self.log.append((self.subject, kwargs["q"], kwargs.get("corpora")))
        if self.subject == f"broken@{DOMAIN}":
            raise RuntimeError("403 for this user")
        return {"files": list(DRIVE.get(self.subject, []))}


def _visibility(when, owner, doc_id, title, old, new):
    """A Drive audit event, in the shape the live dev tenant returned."""
    return {
        "id": {"time": when, "applicationName": "drive"},
        "events": [
            {
                "name": "change_document_visibility",
                "parameters": [
                    {"name": "doc_id", "value": doc_id},
                    {"name": "doc_title", "value": title},
                    {"name": "doc_type", "value": "document"},
                    {"name": "owner", "value": f"{owner}@{DOMAIN}"},
                    {"name": "old_visibility", "value": old},
                    {"name": "visibility", "value": new},
                ],
            }
        ],
    }


#: Newest first, as the Reports API returns them.
AUDIT_LOG = [
    _visibility(
        "2026-09-29T07:02:58.000Z", "gone", "g1", "Departed owner's file", "private", "people_with_link"
    ),
    _visibility(
        "2026-09-29T06:12:22.000Z", "gone", "g2", "Made public then closed", "people_with_link", "private"
    ),
    _visibility(
        "2026-09-29T05:38:29.000Z", "gone", "g2", "Made public then closed", "private", "people_with_link"
    ),
    _visibility(
        "2026-09-29T04:44:24.000Z", "gone", "g3", "Org only", "private", "people_within_domain_with_link"
    ),
    _visibility(
        "2026-09-29T04:00:00.000Z", "staff1", "s9", "Active owner's file", "private", "people_with_link"
    ),
]


class _Activities:
    def __init__(self, fail):
        self.fail = fail

    def list(self, **kwargs):
        assert kwargs["eventName"] == "change_document_visibility"
        if self.fail:
            raise RuntimeError("403 audit log")
        return {"items": list(AUDIT_LOG)}


class _Client:
    def __init__(self, users, audit_fails=False):
        self.settings = type("S", (), {"max_page_size": 200})()
        self.known_users = users
        self.log: list = []
        self.notes: list[str] = []
        self._lock = threading.Lock()
        self.audit_fails = audit_fails

    def service(self, api, version, *, subject=None, **_):
        return type(
            "Svc",
            (),
            {
                "files": lambda _self: _Files(subject, self.log),
                "activities": lambda _self: _Activities(self.audit_fails),
            },
        )()

    def paginate(self, resource, method, key, **kwargs):
        kwargs.pop("max_pages", None)
        with self._lock:
            return getattr(resource, method)(**kwargs)[key]

    def note_incomplete(self, message):
        self.notes.append(message)


def _user(local, **flags):
    return {"primaryEmail": f"{local}@{DOMAIN}", "suspended": False, "archived": False, **flags}


def test_a_file_owned_by_ordinary_staff_is_found():
    client = _Client([_user("admin"), _user("staff1"), _user("staff2")])
    names = {i["name"] for i in PublicDriveItemsCollector().collect(client)}
    assert "Staff donor list" in names  # the dev-tenant miss
    assert "Shared drive: board" in names  # still found via the admin search


def test_each_user_is_searched_as_themselves_for_files_they_own():
    client = _Client([_user("admin"), _user("staff1")])
    PublicDriveItemsCollector().collect(client)
    per_user = {subject: (q, corpora) for subject, q, corpora in client.log if subject}
    assert set(per_user) == {f"admin@{DOMAIN}", f"staff1@{DOMAIN}"}
    for q, corpora in per_user.values():
        assert q.startswith("'me' in owners and ")
        assert corpora == "user"


def test_a_file_seen_by_two_searches_is_counted_once():
    client = _Client([_user("admin"), _user("staff1")])
    ids = [i["id"] for i in PublicDriveItemsCollector().collect(client)]
    assert sorted(ids) == ["a1", "s1", "sd1"]


def test_suspended_accounts_are_named_as_not_searched_not_silently_skipped():
    client = _Client([_user("admin"), _user("gone", suspended=True), _user("old", archived=True)])
    PublicDriveItemsCollector().collect(client)

    assert not any(subject and "gone" in subject for subject, _, _ in client.log)  # never signed in as
    [note] = client.notes
    assert f"gone@{DOMAIN}" in note and f"old@{DOMAIN}" in note
    assert "could not be searched directly" in note


# -- the audit-log fallback for accounts that cannot be searched ---------------


def test_a_suspended_owners_public_file_is_found_from_the_audit_log():
    """Found on the dev tenant: admin-test1 shared a file publicly, was
    suspended, and the file vanished from the report."""
    client = _Client([_user("admin"), _user("gone", suspended=True)])
    items = {i["id"]: i for i in PublicDriveItemsCollector().collect(client)}

    assert items["g1"]["name"] == "Departed owner's file"
    assert items["g1"]["source"] == "audit_log"
    assert items["g1"]["owners"] == [f"gone@{DOMAIN}"]
    assert items["g1"]["made_public_at"] == "2026-09-29T07:02:58.000Z"


def test_the_latest_visibility_change_wins():
    """Made public, then made private again: not public now, not reported."""
    client = _Client([_user("gone", suspended=True)])
    assert "g2" not in {i["id"] for i in PublicDriveItemsCollector().collect(client)}


def test_organization_only_links_are_not_public():
    client = _Client([_user("gone", suspended=True)])
    assert "g3" not in {i["id"] for i in PublicDriveItemsCollector().collect(client)}


def test_the_log_is_only_used_for_owners_that_could_not_be_searched():
    """An active owner's file is read directly or not at all: the log only
    covers the accounts the search cannot reach."""
    client = _Client([_user("staff1"), _user("gone", suspended=True)])
    ids = {i["id"] for i in PublicDriveItemsCollector().collect(client)}
    assert "s9" not in ids
    assert "s1" in ids  # staff1's real public file, found by searching


def test_the_note_says_what_the_log_covered_and_what_it_did_not():
    client = _Client([_user("gone", suspended=True)])
    PublicDriveItemsCollector().collect(client)
    [note] = client.notes
    assert "found from Google's Drive audit log" in note
    assert "180 days" in note


def test_an_unreadable_audit_log_is_stated():
    client = _Client([_user("gone", suspended=True)], audit_fails=True)
    items = PublicDriveItemsCollector().collect(client)
    assert all(i["source"] == "drive_search" for i in items)
    [note] = client.notes
    assert "audit log could not be read" in note


def test_one_users_failure_is_recorded_and_the_rest_still_run():
    client = _Client([_user("broken"), _user("staff1")])
    names = {i["name"] for i in PublicDriveItemsCollector().collect(client)}
    assert "Staff donor list" in names
    [note] = client.notes
    assert f"broken@{DOMAIN}" in note and "failed" in note


def test_without_a_staff_list_the_gap_is_stated():
    client = _Client([])
    PublicDriveItemsCollector().collect(client)
    [note] = client.notes
    assert "staff list was not available" in note


def test_nothing_is_noted_when_everyone_was_searched():
    client = _Client([_user("admin"), _user("staff1")])
    PublicDriveItemsCollector().collect(client)
    assert client.notes == []


def test_no_link_to_the_file_is_kept():
    client = _Client([_user("staff1")])
    for item in PublicDriveItemsCollector().collect(client):
        assert "webViewLink" not in item
        assert item["owners"] == [f"{item['owners'][0]}"]  # plain addresses, not objects
