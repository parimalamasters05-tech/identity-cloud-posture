"""No machine vocabulary where a person reads.

The week-4 bar: a non-technical reader explains the top three risks back to
you, unaided. A reader cannot do that past "isEnrolledIn2Sv=false", "2 broad
scope(s) across 1 user(s)", "Affected collectors: google.mfa" or "0.35 h" --
all of which were in the dev-tenant report when this test was written.

Three zones, strictest first:
  * cover and executive summary -- the director reads these and nothing else;
  * action plan -- the person doing the work (console paths are fine here);
  * finding evidence and "how to check" text -- the IT contact.
The evidence appendix and methodology are deliberately technical and exempt.
"""

from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from tests.conftest import FIXTURE_NOW, REPO_ROOT

from icp.collectors.google import load_fixture_snapshot
from icp.normalizers.google import normalize
from icp.reporting.renderer import ReportRenderer
from icp.rules import assess

#: Anywhere a person reads.
EVERYWHERE = {
    "rule ID": r"\bGWS-[A-Z]{3}-\d{3}\b",
    "'(s)' plural": r"\w\(s\)",
    # Not preceded by a dot, so "myaccount.google.com" (a place the client goes) passes.
    "collector name": r"(?<![\w.])google\.(?!com\b)[a-z_]+\b",
    "raw field name": r"\b(isEnrolledIn2Sv|isAdmin|lastLoginTime|clientId|userKey)\b",
    "internal tier name": r"\b(admin_equivalent|full_data_write|full_data_read|sign_in_only|metadata_only)\b",
    "decimal hours": r"\b\d+\.\d+ ?h\b",
    "ratio column": r"(?i)value/hr",
    "re-run instruction": r"(?i)re-run this assessment",
    # A typewriter "--" breaks lines badly in the PDF ("a phone / prompt -- all").
    "double hyphen as a dash": r"\s--\s",
}

#: Additionally, on the pages a director reads.
DIRECTOR_ONLY = {
    "acronym API": r"\bAPIs?\b",
    "acronym OAuth": r"\bOAuth\b",
    "acronym 2SV/MFA": r"\b(2SV|MFA)\b",
    "word 'scope'": r"(?i)\bscopes?\b",
    "word 'tenant'": r"(?i)\btenant\b",
    "word 'token'": r"(?i)\btokens?\b",
}


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", html)))


def _violations(text: str, patterns: dict[str, str]) -> list[str]:
    out = []
    for name, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            start = max(0, match.start() - 40)
            out.append(f"{name}: ...{text[start : match.end() + 40]}...")
    return out


def _dev_tenant():
    path = REPO_ROOT / "fixtures" / "google-dev"
    snapshot = load_fixture_snapshot(Path(path), tenant_id="dev")
    return normalize(snapshot), snapshot.collected_at


@pytest.fixture(scope="module", params=["planted", "dev"])
def rendered(request, tenant, matrix):
    if request.param == "planted":
        t, now = tenant, FIXTURE_NOW
    else:
        if not (REPO_ROOT / "fixtures" / "google-dev").exists():
            pytest.skip("no frozen dev-tenant fixture set")
        t, now = _dev_tenant()
    result = assess(t, matrix=matrix, now=now)
    renderer = ReportRenderer()
    context = renderer.build_context(t, result, client_name="X", assessor="Y")

    def page(name: str) -> str:
        return _text(renderer.env.get_template(f"partials/{name}.html").render(**context))

    return {"page": page, "context": context, "result": result}


@pytest.mark.parametrize("page", ["cover", "executive_summary"])
def test_director_pages_are_plain(rendered, page):
    text = rendered["page"](page)
    assert _violations(text, {**EVERYWHERE, **DIRECTOR_ONLY}) == []


def test_action_plan_is_plain(rendered):
    assert _violations(rendered["page"]("action_plan"), EVERYWHERE) == []


def test_evidence_sentences_are_plain(rendered):
    """The bracketed reference keeps the raw field; the sentence must not."""
    problems = []
    for finding in rendered["result"].findings:
        for evidence in finding.evidence:
            problems += _violations(evidence.summary, EVERYWHERE)
    assert problems == []


def test_how_to_check_lines_are_things_the_client_can_do(library):
    for key, entry in library.entries.items():
        assert _violations(entry.verification, EVERYWHERE) == [], key


def test_headline_risks_read_as_sentences_not_titles(rendered):
    """Regression: "3 administrator accounts with no second factor enrolled. In
    plain terms, this means accounts that..." -- a table title glued to a
    definition. Each paragraph now opens with a sentence that has a verb."""
    for risk in rendered["context"]["summary"].headline_risks:
        assert "In plain terms, this means" not in risk.paragraph
        first = risk.paragraph.split(". ")[0]
        assert re.search(r"\b(can|is|are|has|have|was|were|holds?|uses?)\b", first), first
