"""GWS-ADM-001 in the organizations this tool is sold to: small ones.

Found by planning the dev-tenant test: with 9 active staff, 10% is 0.9, so the
rule flagged even a single super-admin -- while its own remediation says "keep
two". The recommended maximum now never drops below 2.
"""

from __future__ import annotations

import pytest
from tests.conftest import FIXTURE_NOW, entity_labels

from icp.normalizers.google import normalize
from icp.rules import assess


def _with_supers(snapshot, matrix, *, supers: int, active: int):
    """The planted tenant cut down to `active` staff with `supers` super-admins."""
    users = [u for u in snapshot.artifacts["google.users"] if not u["suspended"]][:active]
    users = [{**u, "isAdmin": i < supers} for i, u in enumerate(users)]
    # Super-admin also comes from role assignments; drop them so `isAdmin` alone
    # decides who is a super-admin here.
    artifacts = {**snapshot.artifacts, "google.users": users, "google.role_assignments": []}
    result = assess(
        normalize(snapshot.model_copy(update={"artifacts": artifacts})), matrix=matrix, now=FIXTURE_NOW
    )
    return [f for f in result.findings if f.rule_id == "GWS-ADM-001"]


@pytest.mark.parametrize(
    "supers,active,fires",
    [
        (1, 9, False),  # the bug: one super-admin in a 9-person org fired
        (2, 9, False),  # primary + break-glass is the advice, so never a finding
        (3, 9, True),  # the dev tenant today
        (2, 5, False),
        (3, 32, False),  # planted tenant: 10% of 32 is 3
        (4, 32, True),
        (2, 20, False),  # 10% of 20 is 2
        (3, 20, True),
        # (the absolute cap of 4 applies from 40+ staff; the planted tenant has 32)
    ],
)
def test_recommended_maximum_scales_with_size_but_never_below_two(snapshot, matrix, supers, active, fires):
    assert bool(_with_supers(snapshot, matrix, supers=supers, active=active)) is fires


def test_the_finding_states_the_number_it_measured_against(snapshot, matrix):
    [finding] = _with_supers(snapshot, matrix, supers=3, active=9)
    assert finding.evidence[0].observed_values["recommended_maximum"] == 2
    assert "never fewer than 2" in finding.evidence[0].summary
    assert len(entity_labels(finding)) == 3
