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

from icp.models.enums import CheckFamily, Platform, ScopeTier, Severity
from icp.models.finding import Finding
from icp.normalizers.base import Application, NormalizedTenant
from icp.reporting import plain
from icp.reporting.consolidation import consolidate
from icp.reporting.executive_summary import build as build_summary
from icp.reporting.executive_summary import build_combined as build_combined_summary
from icp.reporting.platform_text import combined as combined_text
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
        self.env.globals["access"] = _access
        self.env.globals["platform_name"] = lambda finding: for_platform(finding.platform).name

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
            "scope_statement": _scope_statement(tenant, engagement_ref),
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
            # A single-platform report is a combined report with one part: the
            # same templates render both, so their wording cannot drift apart.
            "combined": False,
            "parts": [self._part(tenant, engagement_ref)],
        }

    @staticmethod
    def _part(tenant: NormalizedTenant, engagement_ref: str = "") -> dict[str, Any]:
        """What the per-platform sections (access method, permissions,
        read-only proof, applications, limitations) need for one platform."""
        text = for_platform(tenant.platform)
        permissions = _scopes_for_claims(tenant)
        return {
            "platform": text,
            "tenant": tenant,
            "snapshot": tenant.snapshot,
            "scope_statement": _scope_statement(tenant, engagement_ref),
            "write_capable_scopes": text.write_capable(permissions),
            "content_capable_scopes": text.content_capable(permissions),
            "read_request_count": sum(1 for c in tenant.snapshot.api_calls if c.method in ("GET", "HEAD")),
            "applications": tenant.applications,
            "token_log": tenant.token_log,
        }

    def build_combined_context(
        self,
        assessed: list[tuple[NormalizedTenant, AssessmentResult]],
        *,
        client_name: str,
        assessor: str,
        engagement_ref: str = "",
    ) -> dict[str, Any]:
        """One report for a client on several platforms (the brief's week 5:
        "one command against a mixed-platform client produces one coherent report").

        One rating, one ranked action plan and one findings section across
        every platform, each finding tagged with its platform; the access
        method, permissions, read-only proof and connected applications are
        given per platform, because those differ.
        """
        if len(assessed) < 2:
            raise ValueError("A combined report needs at least two platforms")
        tenants = [t for t, _ in assessed]
        text = combined_text([t.platform for t in tenants])

        findings = [f for _, r in assessed for f in r.findings]
        actionable = [f for f in findings if f.severity != Severity.INFO]
        coverage_notes = [f for f in findings if f.severity == Severity.INFO]
        self._assert_content_complete(findings)

        entries = consolidate(actionable)
        leads = [e.finding for e in entries]
        folded_into = {r.finding_id: e.finding for e in entries for r in e.related}
        ranked = rank(leads, limit=10, dedupe_by_action=True)
        framework = load_framework()

        by_family: dict[str, list[dict[str, Any]]] = {}
        for entry in sorted(entries, key=lambda e: (-e.finding.risk_score, e.finding.finding_id)):
            context = self._finding_context(entry.finding)
            context["related"] = entry.related
            title = _family_title(entry.finding.check_family, text.family_titles)
            by_family.setdefault(title, []).append(context)

        appendix_by_family: dict[str, list[dict[str, Any]]] = {}
        for finding in sorted(actionable, key=lambda f: (-f.risk_score, f.finding_id)):
            context = self._finding_context(finding)
            context["shown_under"] = folded_into.get(finding.finding_id)
            title = _family_title(finding.check_family, text.family_titles)
            appendix_by_family.setdefault(title, []).append(context)

        lead_counts = {str(s): 0 for s in Severity}
        for finding in leads:
            lead_counts[str(finding.severity)] += 1

        passed_areas = []
        degraded_areas = []
        for tenant, result in assessed:
            name = for_platform(tenant.platform).name
            own = [f for f in actionable if f.platform == tenant.platform]
            for area in self._passed_areas(tenant, result, own):
                passed_areas.append({**area, "title": f"{name}: {area['title']}"})
            degraded_areas += [
                f"{name}: {_COLLECTOR_AREAS.get(c, c)}"
                for c in tenant.snapshot.degraded_collectors()
                if c not in _COVER_ONLY_COLLECTORS
            ]

        parts = [self._part(t, engagement_ref) for t in tenants]
        any_write = any(p["write_capable_scopes"] for p in parts)
        any_content = any(p["content_capable_scopes"] for p in parts)
        caveat = " Every permission used can only read."
        if any_write or any_content:
            caveat = (
                " Not every permission is limited to settings: one could in principle remove "
                "connections between staff accounts and outside applications, and one could open "
                "file contents. The tool is built so that it cannot send any change or request a "
                "file's contents, and it did neither."
                if any_write and any_content
                else (_WRITE_CAVEAT if any_write else _CONTENT_CAVEAT)
            )

        return {
            "generated_at": datetime.now(UTC),
            "client_name": client_name,
            "assessor": assessor,
            "engagement_ref": engagement_ref,
            "tenant": tenants[0],
            "coverage": tenants[0].coverage,
            "snapshot": tenants[0].snapshot,
            "summary": build_combined_summary(tenants, leads + coverage_notes, self.library),
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
            "applications": [],
            "token_log": None,
            "appendix_by_family": appendix_by_family,
            "passed_areas": passed_areas,
            "coverage_notes": [self._finding_context(f) for f in coverage_notes],
            "framework": framework,
            "framework_rows": self._framework_rows(actionable, framework),
            "matrix": self.matrix,
            "matrix_rows": self.matrix.as_table(),
            "scope_statement": {
                "examined": list(text.examined),
                "not_examined": list(text.not_examined),
                "method": _authorized(text.method_opening, engagement_ref)
                + caveat
                + " No setting was changed, and no message or file content was opened.",
                "point_in_time": max(t.snapshot.collected_at for t in tenants),
                "degraded": [c for t in tenants for c in t.snapshot.degraded_collectors()],
            },
            "platform": text,
            "write_capable_scopes": [],
            "content_capable_scopes": [],
            "read_request_count": sum(p["read_request_count"] for p in parts),
            "degraded": [c for t in tenants for c in t.snapshot.degraded_collectors()],
            "degraded_areas": degraded_areas,
            "rules_failed": [x for _, r in assessed for x in r.rules_failed],
            "combined": True,
            "parts": parts,
        }

    def render_combined(
        self,
        assessed: list[tuple[NormalizedTenant, AssessmentResult]],
        output_dir: Path,
        *,
        client_name: str,
        assessor: str,
        engagement_ref: str = "",
        basename: str | None = None,
    ) -> RenderResult:
        context = self.build_combined_context(
            assessed, client_name=client_name, assessor=assessor, engagement_ref=engagement_ref
        )
        html = self.env.get_template("report.html").render(**context)

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        latest = max((t.snapshot for t, _ in assessed), key=lambda s: s.collected_at)
        stem = basename or f"{_slug(client_name)}__combined__{latest.snapshot_id}"

        html_path = output_dir / f"{stem}.html"
        html_path.write_text(html, encoding="utf-8")
        pdf_path, pdf_error = self._render_pdf(html, output_dir / f"{stem}.pdf")
        return RenderResult(html_path=html_path, pdf_path=pdf_path, pdf_error=pdf_error)

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
                # A clean age check means something only if the dates were there.
                dated = (
                    tenant.platform == Platform.MICROSOFT_365
                    and family in (CheckFamily.STALE_ACCOUNTS, CheckFamily.ADMIN_ROLE_SPRAWL)
                    and tenant.coverage.get("sign_in_data_available")
                )
                note = (
                    " Microsoft supplied last sign-in dates, so the unused-account checks ran."
                    if dated
                    else ""
                )
                areas.append({"title": title, "checks": checks, "note": note})
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


#: Microsoft: the "Users" column already says whose data. "Read all data"
#: beside an app one person approved for their own mailbox overstated it.
_M365_TIER_LABELS = {
    ScopeTier.FULL_DATA_WRITE: "Read and change mail or files",
    ScopeTier.FULL_DATA_READ: "Read mail or files",
    ScopeTier.SCOPED_DATA: "Limited data",
    ScopeTier.METADATA_ONLY: "Directory details only",
}


def _access(app: Application, platform_name: str) -> dict[str, str]:
    """The inventory's "Highest access" cell: a label, and for Microsoft the
    permission names behind it, so the label can be checked against the portal."""
    if platform_name != "Microsoft 365":
        return {"label": _tier_label(app.max_tier), "detail": ""}
    if app.first_party_kind == "assessor":
        return {
            "label": "Read-only",
            "detail": (
                f"{len(app.scopes)} read permissions, listed under Methodology; "
                "used for settings and sharing details only"
            ),
        }
    names = sorted(s for s in app.scopes if s not in ("openid", "profile", "email", "offline_access"))
    shown = ", ".join(names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else "")
    return {"label": _M365_TIER_LABELS.get(app.max_tier, _tier_label(app.max_tier)), "detail": shown}


def _family_title(family: CheckFamily, overrides: dict[CheckFamily, str]) -> str:
    return overrides.get(family) or _FAMILY_TITLES.get(family, str(family))


def _app_kind(app: Application) -> str:
    return {
        "developer_tool": "Google developer tool",
        "device_sign_in": "Google browser or device sign-in",
        "assessor": "This assessment (remove afterwards)",
        "app_only": "Works without a user",
        "microsoft": "Microsoft's own",
    }.get(app.first_party_kind or "", "Third-party")


#: Accurate, not reassuring: one permission Google requires could, in principle,
#: change something. What we can promise is behaviour.
_WRITE_CAVEAT = (
    " One permission Google requires for this review could in principle remove "
    "connections between staff accounts and outside applications; the tool is built "
    "so that it cannot send any change, and none was made."
)
#: Microsoft: read-only, but one permission could open file contents.
_CONTENT_CAVEAT = (
    " Every permission used can only read, but one could in principle open file contents; "
    "the tool reads only who each file is shared with, and is built so that it cannot "
    "request a file's contents."
)


def _scopes_for_claims(tenant: NormalizedTenant) -> tuple[str, ...]:
    """The scopes the report's access claims must be true of.

    A fixture snapshot records none, but the demo report is what a prospect
    reads: its claims must hold for what a real run requests.
    """
    return tenant.snapshot.scopes_used or (*sorted_scopes(), *optional_scopes())


#: The letter is claimed only when the run names it. A report produced without
#: an engagement reference once said "under a signed authorization letter" for a
#: lab tenant that had none.
_LETTER = ", under a signed authorization letter."
_GRANTED = ", using access an administrator of the organization granted for this review."


def _authorized(method_opening: str, engagement_ref: str) -> str:
    return method_opening if engagement_ref else method_opening.replace(_LETTER, _GRANTED)


def _scope_statement(tenant: NormalizedTenant, engagement_ref: str = "") -> dict[str, Any]:
    """What was and was not examined. Page one, for everyone."""
    text = for_platform(tenant.platform)
    permissions = _scopes_for_claims(tenant)
    if text.write_capable(permissions):
        caveat = _WRITE_CAVEAT
    elif text.content_capable(permissions):
        caveat = _CONTENT_CAVEAT
    else:
        caveat = " Every permission used can only read."
    return {
        "examined": list(text.examined),
        "not_examined": list(text.not_examined),
        "method": (
            _authorized(text.method_opening, engagement_ref)
            + caveat
            + " No setting was changed, and no message or file content was opened."
        ),
        "point_in_time": tenant.snapshot.collected_at,
        "degraded": list(tenant.snapshot.degraded_collectors()),
    }


def _slug(value: str) -> str:
    return "".join(c.lower() if c.isalnum() else "-" for c in value).strip("-") or "client"
