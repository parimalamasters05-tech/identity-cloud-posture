"""Report rendering.

HTML via Jinja2, then PDF via WeasyPrint. HTML is always produced; PDF is
produced when WeasyPrint and its system libraries are available, and its absence
degrades to a clear message rather than a stack trace.

Two design constraints from the brief drive the templates:
  * the report is printed in greyscale for a board packet, so nothing may depend
    on colour to carry meaning;
  * two audiences read different pages and never the same ones.

Jinja autoescaping is on. Findings contain client-controlled strings -- file
names, application names, display names -- and a report is a document that gets
forwarded, so unescaped output would be a stored-XSS vector in the HTML
deliverable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from icp.models.enums import CheckFamily, ScopeTier, Severity
from icp.models.finding import Finding
from icp.normalizers.base import Application, NormalizedTenant
from icp.reporting import plain
from icp.reporting.consolidation import consolidate
from icp.reporting.executive_summary import build as build_summary
from icp.reporting.platform_text import for_platform
from icp.reporting.remediation import RemediationLibrary, load_framework
from icp.risk import scoring
from icp.risk.ranking import rank
from icp.risk.severity import RiskMatrix
from icp.rules.base import rules_for
from icp.rules.engine import AssessmentResult
from icp.security.scopes import optional_scopes, sorted_scopes

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"

_FAMILY_TITLES = {
    CheckFamily.MFA_COVERAGE: "Two-step verification coverage",
    CheckFamily.ADMIN_ROLE_SPRAWL: "Administrative access",
    CheckFamily.STALE_ACCOUNTS: "Unused and departed accounts",
    CheckFamily.SERVICE_ACCOUNT_PRIVILEGE: "Application privilege",
    CheckFamily.EXTERNAL_SHARING: "External and public sharing",
    CheckFamily.LOGGING_READINESS: "Audit and logging readiness",
    CheckFamily.OAUTH_GRANTS: "Third-party application access",
}


@dataclass(frozen=True)
class RenderResult:
    html_path: Path
    pdf_path: Path | None
    pdf_error: str | None = None


class ReportRenderer:
    def __init__(
        self,
        *,
        library: RemediationLibrary | None = None,
        matrix: RiskMatrix | None = None,
        template_dir: Path | None = None,
    ) -> None:
        self.library = library or RemediationLibrary.load_default()
        self.matrix = matrix or RiskMatrix.load_default()
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir or TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            undefined=StrictUndefined,  # a missing variable fails the build, not the client's trust
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters["severity_label"] = _severity_label
        self.env.filters["duration"] = plain.duration
        self.env.filters["long_date"] = _long_date
        self.env.globals["tier_label"] = _tier_label
        self.env.globals["app_kind"] = _app_kind

    # -- context ---------------------------------------------------------------

    def build_context(
        self,
        tenant: NormalizedTenant,
        result: AssessmentResult,
        *,
        client_name: str,
        assessor: str,
        engagement_ref: str = "",
    ) -> dict[str, Any]:
        actionable = [f for f in result.findings if f.severity != Severity.INFO]
        coverage_notes = [f for f in result.findings if f.severity == Severity.INFO]

        self._assert_content_complete(result.findings)

        # Client-facing pages show one entry per application; the appendix and
        # the JSON findings file keep every rule's finding for traceability.
        entries = consolidate(actionable)
        leads = [e.finding for e in entries]
        folded_into = {r.finding_id: e.finding for e in entries for r in e.related}

        # Deduplicated: the plan lists actions, not findings.
        ranked = rank(leads, limit=10, dedupe_by_action=True)
        framework = load_framework()

        by_family: dict[str, list[dict[str, Any]]] = {}
        for entry in sorted(entries, key=lambda e: (-e.finding.risk_score, e.finding.finding_id)):
            context = self._finding_context(entry.finding)
            context["related"] = entry.related
            by_family.setdefault(self._family_title(entry.finding), []).append(context)

        appendix_by_family: dict[str, list[dict[str, Any]]] = {}
        for finding in sorted(actionable, key=lambda f: (-f.risk_score, f.finding_id)):
            context = self._finding_context(finding)
            context["shown_under"] = folded_into.get(finding.finding_id)
            appendix_by_family.setdefault(self._family_title(finding), []).append(context)

        lead_counts = {str(s): 0 for s in Severity}
        for finding in leads:
            lead_counts[str(finding.severity)] += 1

        return {
            "generated_at": datetime.now(UTC),
            "client_name": client_name,
            "assessor": assessor,
            "engagement_ref": engagement_ref,
            "tenant": tenant,
            "coverage": tenant.coverage,
            "snapshot": tenant.snapshot,
            "summary": build_summary(tenant, leads + coverage_notes, self.library),
            "counts": lead_counts,
            "total_findings": len(leads),
            "total_checks_flagged": len(actionable),
            "action_plan": [
                {
                    "rank": entry.rank,
                    "risk_per_hour": entry.risk_per_hour,
                    "finding": entry.finding,
                    "covers": entry.covers,
                    "also_resolves": entry.also_resolves,
                    "remediation": self.library.get(entry.finding.remediation_key),
                }
                for entry in ranked
            ],
            "findings_by_family": by_family,
            "applications": tenant.applications,
            "token_log": tenant.token_log,
            "appendix_by_family": appendix_by_family,
            "passed_areas": self._passed_areas(tenant, result, actionable),
            "coverage_notes": [self._finding_context(f) for f in coverage_notes],
            "framework": framework,
            "framework_rows": self._framework_rows(actionable, framework),
            "matrix": self.matrix,
            "matrix_rows": self.matrix.as_table(),
            "scope_statement": _scope_statement(tenant),
            "platform": for_platform(tenant.platform),
            # Judged by the platform's own rule: Graph read permissions do not
            # end in ".readonly", and the Google rule once called all nine writes.
            "write_capable_scopes": for_platform(tenant.platform).write_capable(_scopes_for_claims(tenant)),
            "content_capable_scopes": for_platform(tenant.platform).content_capable(
                _scopes_for_claims(tenant)
            ),
            "read_request_count": sum(1 for c in tenant.snapshot.api_calls if c.method in ("GET", "HEAD")),
            "degraded": list(tenant.snapshot.degraded_collectors()),
            # Only collectors a check depends on. The organization profile only
            # names the cover; missing it falls back to the domain, not a gap.
            "degraded_areas": [
                _COLLECTOR_AREAS.get(c, c)
                for c in tenant.snapshot.degraded_collectors()
                if c not in _COVER_ONLY_COLLECTORS
            ],
            "rules_failed": result.rules_failed,
        }

    def _finding_context(self, finding: Finding) -> dict[str, Any]:
        return {
            "finding": finding,
            "remediation": self.library.get(finding.remediation_key),
            "score": scoring.explain(finding, self.matrix),
            "family_title": self._family_title(finding),
        }

    @staticmethod
    def _family_title(finding: Finding) -> str:
        return _family_title(finding.check_family, for_platform(finding.platform).family_titles)

    @staticmethod
    def _passed_areas(
        tenant: NormalizedTenant, result: AssessmentResult, actionable: list[Finding]
    ) -> list[dict[str, Any]]:
        """Areas that were checked and came back clean.

        Without this, a family with no findings is invisible, and a reader
        cannot tell "we looked and it was fine" from "we never looked".
        """
        flagged = {f.check_family for f in actionable}
        incomplete = {family for gap in tenant.coverage_gaps for family in gap.families}
        areas: list[dict[str, Any]] = []
        for family in CheckFamily:
            if family in flagged or family in incomplete or not tenant.is_assessable(family):
                continue
            # This platform's checks only: listing both platforms' rules once put
            # Microsoft check names in a Google report's clean areas.
            checks = [
                r.title
                for r in rules_for(family)
                if tenant.platform in r.platforms and r.rule_id not in result.unassessable
            ]
            if checks:
                title = _family_title(family, for_platform(tenant.platform).family_titles)
                areas.append({"title": title, "checks": checks})
        return areas

    def _framework_rows(self, findings: list[Finding], framework: dict[str, Any]) -> list[dict[str, Any]]:
        subcategories = framework.get("subcategories", {})
        rows: list[dict[str, Any]] = []
        for ref, meta in sorted(subcategories.items()):
            related = [f for f in findings if ref in f.framework_refs]
            rows.append(
                {
                    "ref": ref,
                    "function": meta.get("function", ""),
                    "category": meta.get("category", ""),
                    "text": meta.get("text", ""),
                    "finding_count": len(related),
                    "worst_severity": (
                        max(related, key=lambda f: f.severity.rank).severity if related else None
                    ),
                }
            )
        return rows

    def _assert_content_complete(self, findings: list[Finding]) -> None:
        """Refuse to render a report with an empty remediation box."""
        missing = self.library.missing_for({f.remediation_key for f in findings})
        if missing:
            raise KeyError(
                "Cannot render: remediation content missing for "
                + ", ".join(sorted(missing))
                + ". Add it to config/remediation.yaml."
            )

    # -- rendering -------------------------------------------------------------

    def render(
        self,
        tenant: NormalizedTenant,
        result: AssessmentResult,
        output_dir: Path,
        *,
        client_name: str,
        assessor: str,
        engagement_ref: str = "",
        basename: str | None = None,
    ) -> RenderResult:
        context = self.build_context(
            tenant, result, client_name=client_name, assessor=assessor, engagement_ref=engagement_ref
        )
        html = self.env.get_template("report.html").render(**context)

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        stem = basename or f"{_slug(client_name)}__{tenant.snapshot.snapshot_id}"

        html_path = output_dir / f"{stem}.html"
        html_path.write_text(html, encoding="utf-8")

        pdf_path, pdf_error = self._render_pdf(html, output_dir / f"{stem}.pdf")
        return RenderResult(html_path=html_path, pdf_path=pdf_path, pdf_error=pdf_error)

    def _render_pdf(self, html: str, target: Path) -> tuple[Path | None, str | None]:
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]
        except Exception as exc:
            message = (
                "WeasyPrint is unavailable, so only HTML was produced. "
                "Install it with its system dependencies (Pango, cairo) or run in the "
                f"provided Docker image. Detail: {type(exc).__name__}: {exc}"
            )
            logger.warning(message)
            return None, message

        try:
            HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(target))
            return target, None
        except Exception as exc:
            message = f"PDF generation failed: {type(exc).__name__}: {exc}"
            logger.error(message)
            return None, message


def _long_date(value: str) -> str:
    """'2026-09-27' -> '27 September 2026'; anything unparseable is shown as given."""
    from datetime import date

    try:
        day = date.fromisoformat(str(value))
    except ValueError:
        return str(value)
    return f"{day.day} {day:%B %Y}"


def _severity_label(severity: Severity | None) -> str:
    if severity is None:
        return "None"
    return {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Coverage note",
    }[severity]


#: Collector names are internal; the cover page names what was not read.
_COLLECTOR_AREAS = {
    "google.users": "the staff directory",
    "google.groups": "groups",
    "google.roles": "administrator role definitions",
    "google.role_assignments": "who holds which administrator role",
    "google.mfa": "Google's report of which sign-in methods each person uses",
    "google.oauth_tokens": "the applications connected to staff accounts",
    "google.token_activity": "the history of when applications were connected and used",
    "google.drive_settings": "domain settings",
    "google.workspace_policies": "Drive's external-sharing settings",
    "google.public_drive_items": "publicly shared Drive files",
    "google.audit_readiness": "the availability of audit logs",
    "m365.organization": "the organization profile",
    "m365.users": "the staff directory",
    "m365.mfa_registration": "Microsoft's report of registered sign-in methods",
    "m365.auth_methods": "each account's registered sign-in methods",
    "m365.roles": "who holds which administrator role",
    "m365.groups": "groups",
    "m365.service_principals": "the applications present in the organization",
    "m365.graph_permissions": "the access granted to applications",
    "m365.applications": "application sign-in credentials",
    "m365.policies": "sign-in and consent policies",
    "m365.sharepoint_settings": "SharePoint and OneDrive sharing settings",
    "m365.public_files": "publicly shared OneDrive files",
    "m365.audit_readiness": "the availability of sign-in and audit logs",
}

#: Collectors no check depends on.
_COVER_ONLY_COLLECTORS = frozenset({"google.customer"})

_TIER_LABELS = {
    ScopeTier.ADMIN_EQUIVALENT: "Administrator-level",
    ScopeTier.FULL_DATA_WRITE: "Read and change all data",
    ScopeTier.FULL_DATA_READ: "Read all data",
    ScopeTier.SCOPED_DATA: "Limited to its own files",
    ScopeTier.METADATA_ONLY: "Names and listings only",
    ScopeTier.SIGN_IN_ONLY: "Sign-in only",
    ScopeTier.UNKNOWN: "Unclassified — review",
}


def _tier_label(tier: ScopeTier) -> str:
    return _TIER_LABELS.get(tier, str(tier))


def _family_title(family: CheckFamily, overrides: dict[CheckFamily, str]) -> str:
    return overrides.get(family) or _FAMILY_TITLES.get(family, str(family))


def _app_kind(app: Application) -> str:
    return {
        "developer_tool": "Google developer tool",
        "device_sign_in": "Google browser or device sign-in",
        "assessor": "This assessment (remove afterwards)",
        "app_only": "Works without a user",
    }.get(app.first_party_kind or "", "Third-party")


def _scopes_for_claims(tenant: NormalizedTenant) -> tuple[str, ...]:
    """The scopes the report's access claims must be true of.

    A fixture snapshot records none, but the demo report is what a prospect
    reads: its claims must hold for what a real run requests.
    """
    return tenant.snapshot.scopes_used or (*sorted_scopes(), *optional_scopes())


def _scope_statement(tenant: NormalizedTenant) -> dict[str, Any]:
    """What was and was not examined. Page one, for everyone."""
    text = for_platform(tenant.platform)
    permissions = _scopes_for_claims(tenant)
    if text.write_capable(permissions):
        # Accurate, not reassuring: one permission Google requires could, in
        # principle, change something. What we can promise is behaviour.
        caveat = (
            " One permission Google requires for this review could in principle remove "
            "connections between staff accounts and outside applications; the tool is built "
            "so that it cannot send any change, and none was made."
        )
    elif text.content_capable(permissions):
        # Microsoft: read-only, but one permission could open file contents.
        caveat = (
            " Every permission used can only read, but one could in principle open file contents; "
            "the tool reads only who each file is shared with, and is built so that it cannot "
            "request a file's contents."
        )
    else:
        caveat = " Every permission used can only read."
    return {
        "examined": list(text.examined),
        "not_examined": list(text.not_examined),
        "method": (
            text.method_opening
            + caveat
            + " No setting was changed, and no message or file content was opened."
        ),
        "point_in_time": tenant.snapshot.collected_at,
        "degraded": list(tenant.snapshot.degraded_collectors()),
    }


def _slug(value: str) -> str:
    return "".join(c.lower() if c.isalnum() else "-" for c in value).strip("-") or "client"
