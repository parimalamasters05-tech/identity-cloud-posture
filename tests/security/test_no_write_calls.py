"""CI gate: no write-capable API call may exist anywhere in the source.

This wraps `tools/verify_readonly.py` so the check runs as part of the normal
test suite as well as standalone in CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

from verify_readonly import FORBIDDEN_METHODS, scan, scan_file  # noqa: E402

pytestmark = pytest.mark.security


def test_source_tree_contains_no_write_calls():
    violations = scan(REPO_ROOT / "src", REPO_ROOT)
    assert violations == [], "\n".join(str(v) for v in violations)


def test_verifier_detects_a_planted_write_call(tmp_path):
    """A guard that cannot fail is not a guard.

    This proves the scanner actually detects the thing it claims to detect,
    rather than passing because it never looks.
    """
    planted = tmp_path / "bad_collector.py"
    planted.write_text(
        "def go(service):\n    return service.users().delete(userKey='victim@example.com').execute()\n",
        encoding="utf-8",
    )
    violations = scan_file(planted, tmp_path)
    assert any(v.kind == "write-call" and "delete" in v.detail for v in violations)


def test_verifier_detects_a_planted_write_scope(tmp_path):
    planted = tmp_path / "bad_scopes.py"
    planted.write_text('SCOPES = ["https://www.googleapis.com/auth/drive"]\n', encoding="utf-8")
    violations = scan_file(planted, tmp_path)
    assert any(v.kind == "write-scope" for v in violations)


def test_verifier_detects_a_planted_unsafe_verb(tmp_path):
    planted = tmp_path / "bad_verb.py"
    planted.write_text('http.request(url, method="POST")\n', encoding="utf-8")
    violations = scan_file(planted, tmp_path)
    assert any(v.kind == "unsafe-verb" for v in violations)


def test_forbidden_method_list_covers_the_obvious_ones():
    for method in ("insert", "update", "patch", "delete", "batchUpdate", "makeAdmin"):
        assert method in FORBIDDEN_METHODS
