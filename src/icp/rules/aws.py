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
from icp.rules.base import Rule, RuleContext, RuleNotAssessable, register

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
    # Prowler names an inline policy "<user>/<policy>".
    if row["resource_type"] == "AwsIamPolicy" and "/" in name:
        owner, policy = name.split("/", 1)
        return f"{policy} (inline, on {owner})"
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
        # Regions AWS refused to show (a per-region rule only): left out, with
        # a coverage note from the normalizer, rather than reported as failing.
        refused_regions = self._check_inputs(tenant, rows)
        # A resource another finding already covers is left out (a public
        # bucket is not also "shared with another account").
        covered = {
            r["resource_uid"] for r in rows if r["check_id"] in m.except_failing and r["status"] == "FAIL"
        }
        failed = [
            r
            for r in rows
            if r["check_id"] in m.checks
            and r["status"] == "FAIL"
            and r["resource_uid"] not in covered
            and r["region"] not in refused_regions
        ]
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

    def _check_inputs(self, tenant: NormalizedTenant, rows: list[dict[str, Any]]) -> set[str]:
        """Raise RuleNotAssessable where Prowler's verdict cannot be trusted.

        Returns the regions to leave out when a per-region rule was refused in
        some regions but not all.
        """
        m = self.mapped
        skip_regions: set[str] = set()
        if m.needs:
            denied = tenant.snapshot.artifacts.get("aws.denied")
            if not isinstance(denied, dict):
                raise RuleNotAssessable(
                    "Prowler's log was not imported with its results, so a read AWS refused during "
                    "the scan cannot be ruled out, and Prowler reports a pass when that happens."
                )
            refused = [a for a in m.needs if a in denied]
            if refused:
                regions = {r for a in refused for r in denied[a].get("regions", [])}
                checked = {r["region"] for r in rows if r["check_id"] in m.checks} - regions
                if m.collapse == "region" and regions and checked:
                    skip_regions |= regions
                else:
                    by_policy = any(denied[a].get("by_organization_policy") for a in refused)
                    raise RuleNotAssessable(
                        f"AWS refused a read these checks depend on ({', '.join(refused)})"
                        + (
                            ", because of a policy set by the organization that manages this account "
                            "(a service control policy), whatever rights the assessment role has"
                            if by_policy
                            else ""
                        )
                        + ". Prowler reports a pass when that happens, so its result was not used."
                    )
        # Prowler emits nothing for a check that found nothing to check, and
        # nothing for one that crashed or does not exist. Only its log tells the
        # two apart (review, 27 Oct 2026): a check that returned nothing counts as
        # "ran, nothing applicable" only when the log shows no error for it or
        # for its service.
        scan = tenant.snapshot.artifacts.get("aws.scan_errors")
        returned = {r["check_id"] for r in rows if r["check_id"] in m.checks}
        if not isinstance(scan, dict):
            if set(m.checks) - returned:
                raise RuleNotAssessable(
                    "Prowler's log was not imported with its results, so a check that returned "
                    "nothing cannot be told apart from one that failed to run."
                )
        else:
            failed = {c: e for c, e in (scan.get("checks") or {}).items() if c in m.checks}
            if failed:
                raise RuleNotAssessable(
                    f"Prowler's check {', '.join(sorted(failed))} did not run properly, so its result is "
                    f"unknown, not clean. Prowler logged: {next(iter(failed.values()))}"
                )
            service_error = (scan.get("services") or {}).get(m.service)
            if service_error:
                regions = set(service_error.get("regions") or [])
                checked = {r["region"] for r in rows if r["check_id"] in m.checks} - regions - skip_regions
                if m.collapse == "region" and regions and checked:
                    skip_regions |= regions
                else:
                    raise RuleNotAssessable(
                        f"Prowler could not fully read the {m.service} data these checks use"
                        + (f" (in {', '.join(sorted(regions))})" if regions else "")
                        + f", so a missing result is not a pass. Prowler logged: {service_error['messages'][0]}"
                    )
        if m.if_empty and not returned:
            raise RuleNotAssessable(m.if_empty)
        return skip_regions


def _build(mapped: MappedRule) -> type[ProwlerRule]:
    return type(
        "Prowler_" + mapped.rule_id.replace("-", "_"),
        (ProwlerRule,),
        {
            "rule_id": mapped.rule_id,
            "check_family": mapped.family,
            # Neutral: also the heading of a "not assessed" note, where a count
            # ("1 AWS user can...") would read as a finding.
            "title": mapped.many.replace("{n} ", ""),
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
