"""The Prowler check map: which Prowler checks are run for AWS, and how each
failed result becomes one of this tool's findings.

Data, not code (`config/prowler_check_map.yaml`), for the same reason as the
risk matrix: a client who challenges an AWS finding can be shown exactly which
Prowler check produced it and how it was scored.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from icp.models.enums import CheckFamily

DEFAULT_MAP_PATH = Path("config/prowler_check_map.yaml")


@dataclass(frozen=True)
class MappedRule:
    rule_id: str
    family: CheckFamily
    service: str
    checks: tuple[str, ...]
    impact: int
    exposure: int
    noun: str
    one: str
    many: str
    evidence: str
    remediation: str
    framework: tuple[str, ...]
    privileged: bool = False
    #: Skip when this other rule has a finding: it already says so.
    unless: str = ""
    #: "region": one affected item per region, not per resource.
    collapse: str = ""
    #: AWS read actions the checks depend on; refused, the rule is not assessed.
    needs: tuple[str, ...] = ()
    #: Why the rule is not assessed when its checks returned nothing.
    if_empty: str = ""
    #: A resource failing one of these checks is covered by another finding.
    except_failing: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProwlerMap:
    prowler_version: str
    rules: tuple[MappedRule, ...]

    @property
    def checks(self) -> tuple[str, ...]:
        """Every Prowler check to run, in a stable order."""
        return tuple(sorted({c for r in self.rules for c in r.checks}))

    @property
    def services(self) -> dict[str, tuple[str, ...]]:
        """service -> the checks that read it."""
        out: dict[str, set[str]] = {}
        for rule in self.rules:
            out[rule.service] = out.get(rule.service, set()) | set(rule.checks)
        return {s: tuple(sorted(c)) for s, c in sorted(out.items())}


def _find(path: Path) -> Path:
    if path.exists():
        return path
    for parent in [Path.cwd(), *Path(__file__).resolve().parents]:
        if (parent / path).exists():
            return parent / path
    raise FileNotFoundError(f"Prowler check map not found: {path}")


@lru_cache(maxsize=4)
def load(path: Path = DEFAULT_MAP_PATH) -> ProwlerMap:
    data = yaml.safe_load(_find(path).read_text("utf-8")) or {}
    rules = tuple(
        MappedRule(
            rule_id=str(r["id"]),
            family=CheckFamily(r["family"]),
            service=str(r["service"]),
            checks=tuple(r["checks"]),
            impact=int(r["impact"]),
            exposure=int(r["exposure"]),
            noun=str(r["noun"]),
            one=str(r["one"]),
            many=str(r["many"]),
            evidence=str(r["evidence"]),
            remediation=str(r["remediation"]),
            framework=tuple(r.get("framework", ())),
            privileged=bool(r.get("privileged", False)),
            unless=str(r.get("unless", "")),
            collapse=str(r.get("collapse", "")),
            needs=tuple(r.get("needs", ())),
            if_empty=str(r.get("if_empty", "")),
            except_failing=tuple(r.get("except_failing", ())),
        )
        for r in data.get("rules", [])
    )
    return ProwlerMap(prowler_version=str(data.get("prowler_version", "")), rules=rules)
