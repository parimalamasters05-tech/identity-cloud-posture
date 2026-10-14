"""AWS rules: one per entry in the Prowler check map.

Prowler decides pass or fail; this decides what a failure means for the
client: which of the seven check families it belongs to, how it is scored on
the same impact x exposure matrix as every other platform, and how it reads.
The rule classes are built from `config/prowler_check_map.yaml`, so adding an
AWS check is a change to that file, not to code.
"""

from __future__ import annotations

from typing import Any

from icp.models.enums import Platform
from icp.models.finding import AffectedEntity, Evidence, Finding
from icp.normalizers.aws import results
from icp.normalizers.base import NormalizedTenant
from icp.risk.prowler_map import MappedRule
from icp.risk.prowler_map import load as load_map
from icp.rules.base import Rule, RuleContext, register

AWS = (Platform.AWS,)

#: Evidence lines shown per finding; the appendix lists every affected item.
_EVIDENCE_LIMIT = 6


def _label(row: dict[str, Any], mapped: MappedRule) -> str:
    """What the report calls the affected item."""
    if mapped.collapse == "region":
        return row["region"] or "an unnamed region"
    if mapped.noun == "root user":
        return "the root user"
    name = row["resource_name"] or row["resource_uid"].rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    # Prowler names the root user "<root_account>".
    return "the root user" if name.strip("<>") == "root_account" else name


def _key(row: dict[str, Any], mapped: MappedRule) -> str:
    """Identity of the affected item across runs, for the delta."""
    if mapped.collapse == "region":
        return f"region:{row['region']}"
    return row["resource_uid"] or f"{row['resource_type']}:{row['resource_name']}"


class ProwlerRule(Rule):
    """A rule whose verdict comes from Prowler. Subclasses set `mapped`."""

    platforms = AWS
    mapped: MappedRule

    def evaluate(self, tenant: NormalizedTenant, ctx: RuleContext) -> list[Finding]:
        m = self.mapped
        rows = results(tenant)
        failed = [r for r in rows if r["check_id"] in m.checks and r["status"] == "FAIL"]
        if not failed:
            return []
        if m.unless:
            other = next((x for x in load_map().rules if x.rule_id == m.unless), None)
            if other and any(r["check_id"] in other.checks and r["status"] == "FAIL" for r in rows):
                return []

        # One affected item per resource (or region), however many of this
        # rule's checks failed on it.
        by_item: dict[str, dict[str, Any]] = {}
        for row in failed:
            by_item.setdefault(_key(row, m), row)
        items = sorted(by_item.items(), key=lambda kv: _label(kv[1], m))
        n = len(items)

        return [
            self.make_finding(
                tenant,
                ctx,
                title=m.one if n == 1 else m.many.format(n=n),
                entities=[
                    AffectedEntity(id=key, kind=m.noun, label=_label(row, m), is_privileged=m.privileged)
                    for key, row in items
                ],
                evidence=[
                    Evidence(
                        collector="aws.prowler",
                        pointer=f"/aws.prowler/results[check_id={row['check_id']},resource={key}]",
                        summary=m.evidence.format(name=_label(row, m)),
                        observed_values={
                            "prowler_check": row["check_id"],
                            "prowler_result": row["detail"],
                            "region": row["region"],
                        },
                    )
                    for key, row in items[:_EVIDENCE_LIMIT]
                ],
            )
        ]


def _build(mapped: MappedRule) -> type[ProwlerRule]:
    return type(
        "Prowler_" + mapped.rule_id.replace("-", "_"),
        (ProwlerRule,),
        {
            "rule_id": mapped.rule_id,
            "check_family": mapped.family,
            "title": mapped.one,
            "impact": mapped.impact,
            "exposure": mapped.exposure,
            "remediation_key": mapped.remediation,
            "framework_refs": mapped.framework,
            # Prowler emits nothing for a service it could not read; the
            # importer records that, and the rule is then "not assessed".
            "requires_collectors": (f"aws.{mapped.service}",),
            "mapped": mapped,
            "__doc__": f"Prowler: {', '.join(mapped.checks)}",
        },
    )


for _mapped in load_map().rules:
    register(_build(_mapped))
