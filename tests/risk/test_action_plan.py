"""The top-10 action plan: invariants, and the reviewed order.

The brief: "manually review the top 10 output and confirm you agree with the
order. If you don't, the rubric is wrong, not your intuition." The first review
disagreed (a 30-minute medium above two criticals), the rubric was changed, and
the order below is the result. `EXPECTED_TOP_10` pins it: if a rubric change
moves it, this test fails and the new order gets reviewed again, on purpose.
"""

from __future__ import annotations

import pytest

from icp.reporting.renderer import ReportRenderer
from icp.risk.severity import RiskMatrix


def _plan(tenant, result):
    return ReportRenderer().build_context(tenant, result, client_name="X", assessor="Y")["action_plan"]


#: Reviewed 2026-09-28 against the planted tenant. Awaiting the assessor's
#: sign-off -- change this comment when you have reviewed it yourself.
EXPECTED_TOP_10 = [
    "GWS-MFA-001",  # critical: super-admin with no second factor
    "GWS-SHR-001",  # critical: donor list public to anyone with the link; ~30 min
    "GWS-OAU-001",  # critical: apps still reading departed staff's mail
    "GWS-SVC-001",  # critical: app that can administer every account
    "GWS-ADM-002",  # high: dormant super-admin
    "GWS-OAU-002",  # high: NoteTaker reading 13 mailboxes (+ other broad apps)
    "GWS-MFA-003",  # high: admins on phishable second factors
    "GWS-MFA-002",  # high: 8 staff without 2SV
    "GWS-LOG-001",  # high: sign-in log unreadable
    "GWS-SVC-003",  # medium: gcloud login with cloud-platform scope
]


def test_the_reviewed_order_holds(tenant, result):
    assert [e["finding"].rule_id for e in _plan(tenant, result)] == EXPECTED_TOP_10


def test_nothing_outranks_a_more_severe_item(tenant, result):
    """The invariant the first review found broken."""
    ranks = [e["finding"].severity.rank for e in _plan(tenant, result)]
    assert ranks == sorted(ranks, reverse=True)


def test_every_critical_finding_is_in_the_plan(tenant, result):
    """Directly, or as something the same action also resolves."""
    covered = set()
    for entry in _plan(tenant, result):
        covered.add(entry["finding"].finding_id)
        covered |= {f.finding_id for f in entry["also_resolves"]}
    criticals = {f.finding_id for f in result.findings if f.severity.name == "CRITICAL"}
    from icp.reporting.consolidation import consolidate

    leads = {
        e.finding.finding_id for e in consolidate([f for f in result.findings if f.finding_id in criticals])
    }
    assert leads <= covered


# -- effort scaling ------------------------------------------------------------


@pytest.fixture
def matrix_():
    return RiskMatrix.load_default()


@pytest.mark.parametrize(
    "key,items,hours",
    [
        ("sharing.restrict_public_links", 3, 0.55),  # was a flat 3.0
        ("sharing.restrict_public_links", 300, 8.0),  # capped
        ("mfa.enforce_all_users", 8, 1.8),
        ("apps.revoke_admin_equivalent", 1, 2.0),  # flat entries are unchanged
        ("apps.revoke_admin_equivalent", 50, 2.0),
    ],
)
def test_effort_scales_with_items_where_the_fix_is_per_item(matrix_, key, items, hours):
    assert matrix_.effort(key, items=items) == hours


def test_unknown_key_falls_back_to_the_rules_default(matrix_):
    assert matrix_.effort("no.such.key", 1.5, items=40) == 1.5
