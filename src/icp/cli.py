"""Command-line entry point.

Pipeline stages are separate commands on purpose. `collect` is the only one that
touches a client tenant; everything after it works on a local snapshot. That
means analysis and report iteration happen with no further access to the
client's environment, which is both faster and a smaller promise to keep.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import click

from icp import __version__
from icp.config import ConfigError, Settings
from icp.security.redaction import configure_logging
from icp.storage._permissions import private_dir, write_private
from icp.storage.paths import file_in

logger = logging.getLogger("icp")


def _settings(ctx: click.Context) -> Settings:
    return ctx.obj["settings"]


def _fail(message: str) -> None:
    click.secho(f"error: {message}", fg="red", err=True)
    sys.exit(1)


def _encrypt_live(settings: Settings, no_encrypt: bool) -> bool:
    """Whether a live snapshot is encrypted. Always, unless this is a test tenant.

    --no-encrypt or ICP_ENCRYPT_AT_REST=false alone used to be enough to write
    a client's tenant in plaintext. Now plaintext also needs
    ICP_TEST_ENVIRONMENT=true, which every report from it then states on its cover.
    """
    if settings.encrypt_at_rest and not no_encrypt:
        return True
    if not settings.test_environment:
        _fail(
            "refusing to write an unencrypted snapshot of a live tenant "
            f"({'--no-encrypt' if no_encrypt else 'ICP_ENCRYPT_AT_REST=false'}). Client data is "
            "always encrypted at rest. Only for your own deliberately misconfigured test tenant, "
            "set ICP_TEST_ENVIRONMENT=true (its reports then say so on the cover)."
        )
    click.secho(
        "warning: writing an unencrypted snapshot (ICP_TEST_ENVIRONMENT=true: test tenant only).",
        fg="yellow",
        err=True,
    )
    return False


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--verbose", "-v", is_flag=True, help="Debug logging.")
@click.option("--json-logs", is_flag=True, help="Structured log output.")
@click.version_option(__version__, prog_name="icp")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, json_logs: bool) -> None:
    """Identity & Cloud Posture Health Check -- read-only assessment tool."""
    configure_logging(logging.DEBUG if verbose else logging.INFO, json_output=json_logs)
    ctx.ensure_object(dict)
    ctx.obj["settings"] = Settings.from_env()


# -- collect -------------------------------------------------------------------


@cli.command()
@click.option("--tenant", help="Override ICP_TENANT_ID.")
@click.option(
    "--no-encrypt",
    is_flag=True,
    help="Write plaintext. Needs ICP_TEST_ENVIRONMENT=true (test tenants only).",
)
@click.option("--fixtures", is_flag=True, help="Build a snapshot from frozen fixtures, offline.")
@click.pass_context
def collect(ctx: click.Context, tenant: str | None, no_encrypt: bool, fixtures: bool) -> None:
    """Retrieve tenant configuration and write a snapshot.

    The only command that contacts a client environment.
    """
    from icp.collectors import google as google_collectors
    from icp.security.audit_log import write_audit_trail
    from icp.storage.snapshot_store import SnapshotStore

    settings = _settings(ctx)
    if tenant:
        settings = Settings(**{**settings.__dict__, "tenant_id": tenant})

    # Decided before collecting, so a refusal costs no read of the client's tenant.
    # Fixtures hold no client data; they are written as they always were.
    encrypt = False if fixtures else _encrypt_live(settings, no_encrypt)

    try:
        if fixtures:
            click.echo("Building snapshot from fixtures (offline, no credentials used).")
            snapshot = google_collectors.load_fixture_snapshot(
                settings.fixture_dir / "google", tenant_id=settings.tenant_id or "dev-fixture"
            )
        else:
            snapshot = google_collectors.collect(settings)
    except ConfigError as exc:
        _fail(str(exc))
    except Exception as exc:
        _fail(f"{type(exc).__name__}: {exc}")

    # Writing is as failure-prone as collecting -- a missing ICP_SNAPSHOT_KEY is
    # the single most common second-run mistake, and its exception already
    # carries the fix. Let the operator read it instead of a stack trace.
    try:
        store = SnapshotStore(settings.snapshot_dir, encrypt=encrypt)
        path = store.save(snapshot)

        if snapshot.api_calls:
            trail = write_audit_trail(
                store.trail_path_for(snapshot),
                list(snapshot.api_calls),
                tenant_id=snapshot.tenant_id,
            )
            click.echo(f"Read-only call trail: {trail}")
    except Exception as exc:
        _fail(f"{type(exc).__name__}: {exc}")

    click.secho(f"Snapshot written: {path}", fg="green")
    click.echo(f"  artifacts: {len(snapshot.artifacts)}   API calls: {len(snapshot.api_calls)}")
    if snapshot.started_at:
        elapsed = (snapshot.collected_at - snapshot.started_at).total_seconds()
        budget = google_collectors.COLLECTION_BUDGET_SECONDS
        click.echo(
            f"  collection window (UTC): {snapshot.started_at:%Y-%m-%d %H:%M:%S} to "
            f"{snapshot.collected_at:%H:%M:%S}  -- filter your Admin audit log to this"
        )
        click.secho(
            f"  duration: {elapsed:.0f}s (budget {budget}s)",
            fg="yellow" if elapsed > budget else None,
        )
    if snapshot.errors:
        click.secho(f"  degraded collectors: {', '.join(snapshot.degraded_collectors())}", fg="yellow")
    for scope in snapshot.scopes_refused:
        click.secho(f"  scope not granted (add to domain-wide delegation): {scope}", fg="yellow")


# -- assess --------------------------------------------------------------------


@cli.command()
@click.option("--snapshot", "snapshot_path", type=click.Path(exists=True, path_type=Path))
@click.option("--tenant", help="Use the latest snapshot for this tenant.")
@click.pass_context
def assess(ctx: click.Context, snapshot_path: Path | None, tenant: str | None) -> None:
    """Run the rules engine against a snapshot and write findings."""
    from icp.normalizers import normalize_snapshot as normalize
    from icp.rules import assess as run_rules
    from icp.storage.finding_store import FindingStore
    from icp.storage.snapshot_store import SnapshotStore

    settings = _settings(ctx)
    store = SnapshotStore(settings.snapshot_dir, encrypt=False)

    snapshot = _load_snapshot(store, snapshot_path, tenant or settings.tenant_id)
    tenant_view = normalize(snapshot)
    # Judged as of collection, not as of today: re-assessing a months-old
    # snapshot must give the findings it gave then ("dormant 90 days" is 90
    # days before the snapshot), or a delta against it compares two clocks.
    result = run_rules(tenant_view, now=snapshot.collected_at)

    findings_path = FindingStore(settings.output_dir).save(
        result, tenant_id=snapshot.tenant_id, snapshot_id=snapshot.snapshot_id
    )

    counts = result.counts_by_severity()
    click.secho(f"Findings written: {findings_path}", fg="green")
    click.echo(
        f"  critical {counts['critical']}  high {counts['high']}  "
        f"medium {counts['medium']}  low {counts['low']}  coverage notes {counts['info']}"
    )
    if result.rules_failed:
        for rule_id, error in result.rules_failed:
            click.secho(f"  rule {rule_id} failed: {error}", fg="yellow", err=True)


# -- report --------------------------------------------------------------------


@cli.command()
@click.option(
    "--snapshot",
    "snapshot_paths",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Snapshot to report on. Give it once per platform for one combined report.",
)
@click.option(
    "--previous-snapshot",
    "previous_paths",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help=(
        "An earlier snapshot of the same platform. Adds a 'Progress since the previous "
        "review' section. Give it once per platform to compare."
    ),
)
@click.option(
    "--latest",
    is_flag=True,
    help=(
        "Use the newest snapshot of every configured platform (Google: ICP_TENANT_ID; "
        "Microsoft: ICP_M365_TENANT_LABEL, default m365; AWS: ICP_AWS_TENANT_LABEL, default aws)."
    ),
)
@click.option(
    "--with-progress",
    is_flag=True,
    help="With --latest: compare each platform with its previous snapshot.",
)
@click.option("--tenant", help="Use the latest snapshot for this tenant.")
@click.option(
    "--client-name",
    default="",
    help=(
        "Override the organization name on the cover. Default: the name in the client's "
        "own account profile, or failing that its primary domain."
    ),
)
@click.option(
    "--assessor",
    envvar="ICP_ASSESSOR",
    default="",
    help="Your name or company, for the cover page. Default: $ICP_ASSESSOR.",
)
@click.option(
    "--test-environment",
    is_flag=True,
    envvar="ICP_TEST_ENVIRONMENT",
    help="Say on the cover and in the summary that this is a deliberately misconfigured test setup.",
)
@click.option("--engagement-ref", default="", help="Reference from the authorization letter.")
@click.option(
    "--max-age-days",
    type=click.IntRange(min=0),
    envvar="ICP_MAX_SNAPSHOT_AGE_DAYS",
    default=7,
    show_default=True,
    help="A snapshot collected longer ago than this is reported only with --allow-stale.",
)
@click.option(
    "--allow-stale",
    is_flag=True,
    help="Report snapshots older than --max-age-days as they were (their dates are on the cover).",
)
@click.pass_context
def report(
    ctx: click.Context,
    snapshot_paths: tuple[Path, ...],
    previous_paths: tuple[Path, ...],
    latest: bool,
    with_progress: bool,
    tenant: str | None,
    client_name: str,
    assessor: str,
    engagement_ref: str,
    test_environment: bool,
    max_age_days: int,
    allow_stale: bool,
) -> None:
    """Generate the client-facing report.

    With one snapshot (or none: the latest for the tenant), a report for that
    platform. With --snapshot given once per platform, one combined report.
    Every snapshot is checked against this engagement's tenant and account
    identifiers (ICP_GOOGLE_PRIMARY_DOMAIN, ICP_M365_TENANT_ID, ICP_AWS_ROLE_ARN),
    and one older than --max-age-days needs --allow-stale.
    """
    from icp.normalizers import normalize_snapshot as normalize
    from icp.reporting.renderer import ReportRenderer
    from icp.rules import assess as run_rules
    from icp.storage.snapshot_store import SnapshotStore

    # Checked before any work: a cover reading "Client" / "Assessor" looks like
    # a template, and it used to be produced silently whenever .env lacked the
    # names (docker-compose filled in those words as defaults).
    assessor = _cover_name(assessor, "assessor", "--assessor", "ICP_ASSESSOR")
    override = _client_override(client_name)

    settings = _settings(ctx)
    store = SnapshotStore(settings.snapshot_dir, encrypt=False)

    if latest:
        if snapshot_paths or previous_paths:
            _fail("--latest picks the snapshots itself; leave out --snapshot and --previous-snapshot.")
        snapshot_paths, previous_paths = _latest_per_platform(store, settings, with_progress)
    elif with_progress:
        _fail(
            "--with-progress works with --latest; otherwise name the earlier snapshot with --previous-snapshot."
        )

    def assessed(path: Path | None, *, current: bool = True):  # type: ignore[no-untyped-def]
        snapshot = _load_snapshot(store, path, tenant or settings.tenant_id)
        _check_identity(snapshot, path)
        if current:
            _check_age(snapshot, path, max_age_days, allow_stale)
        view = normalize(snapshot)
        # As of collection, like `assess`: a report written weeks later must
        # show the findings the snapshot had, not ones aged by today's date.
        return view, run_rules(view, now=snapshot.collected_at)

    def progress_for(pairs: list) -> list:  # type: ignore[type-arg]
        """Each earlier snapshot, compared with this report's snapshot of the
        same platform. Re-assessed from the snapshot, so both sides are judged
        by today's rules."""
        from icp.reporting.progress import build as build_progress

        sections = []
        for path in previous_paths:
            earlier = assessed(path, current=False)
            match = next((p for p in pairs if p[0].platform == earlier[0].platform), None)
            if match is None:
                _fail(f"--previous-snapshot {path.name} is for a platform this report does not cover.")
                continue
            try:
                sections.append(build_progress(earlier, match))
            except ValueError as exc:
                _fail(f"--previous-snapshot {path.name}: {exc}.")
        return sections

    if len(snapshot_paths) > 1:
        pairs = [assessed(path) for path in snapshot_paths]
        platforms = [view.platform for view, _ in pairs]
        if len(set(platforms)) != len(platforms):
            _fail("A combined report takes one snapshot per platform; two of these are the same platform.")
        # Prefer a real organization name over one that is just the domain
        # (seen live: Google's profile name was "identityposturelab.com" while
        # Microsoft's was "Identity Posture Lab").
        named = next(
            (v for v, _ in pairs if v.organization_name and v.organization_name != v.primary_domain),
            next((v for v, _ in pairs if v.organization_name), pairs[0][0]),
        )
        client_name = _client_name(override, named)
        rendered = ReportRenderer(test_environment=test_environment).render_combined(
            pairs,
            settings.output_dir,
            client_name=client_name,
            assessor=assessor,
            engagement_ref=engagement_ref,
            progress=progress_for(pairs),
        )
        click.echo("Combined report for: " + ", ".join(str(p).replace("_", " ") for p in platforms))
    else:
        tenant_view, result = assessed(snapshot_paths[0] if snapshot_paths else None)
        client_name = _client_name(override, tenant_view)
        rendered = ReportRenderer(test_environment=test_environment).render(
            tenant_view,
            result,
            settings.output_dir,
            client_name=client_name,
            assessor=assessor,
            engagement_ref=engagement_ref,
            progress=progress_for([(tenant_view, result)]),
        )

    if previous_paths:
        click.echo(f"Progress section: compared with {len(previous_paths)} earlier snapshot(s).")
    click.secho(f"HTML report: {rendered.html_path}", fg="green")
    if rendered.pdf_path:
        click.secho(f"PDF report:  {rendered.pdf_path}", fg="green")
    else:
        click.secho(f"PDF not generated. {rendered.pdf_error}", fg="yellow", err=True)


# -- run -----------------------------------------------------------------------


@cli.command()
@click.option("--client-name", default="", help="Override the name Google reports for the organization.")
@click.option("--assessor", envvar="ICP_ASSESSOR", default="")
@click.option("--fixtures", is_flag=True, help="Offline run against frozen fixtures.")
@click.option("--no-encrypt", is_flag=True, help="Write plaintext. Needs ICP_TEST_ENVIRONMENT=true.")
@click.pass_context
def run(ctx: click.Context, client_name: str, assessor: str, fixtures: bool, no_encrypt: bool) -> None:
    """Collect, assess, and report in one pass."""
    # Before collecting: failing at the report step would waste a live read.
    # (The client's name itself comes from the collection, so only an explicit
    # override can be checked here.)
    _client_override(client_name)
    assessor = _cover_name(assessor, "assessor", "--assessor", "ICP_ASSESSOR")
    ctx.invoke(collect, no_encrypt=no_encrypt, fixtures=fixtures)
    ctx.invoke(assess)
    # Frozen fixtures keep the date they were captured on.
    ctx.invoke(report, client_name=client_name, assessor=assessor, allow_stale=fixtures)


# -- delta ---------------------------------------------------------------------


@cli.command()
@click.option("--previous", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--current", required=True, type=click.Path(exists=True, path_type=Path))
@click.pass_context
def delta(ctx: click.Context, previous: Path, current: Path) -> None:
    """Compare two findings files. This is the retainer product."""
    from icp.delta.compare import compare
    from icp.storage.finding_store import FindingStore, IncompatibleFindings

    settings = _settings(ctx)
    store = FindingStore(settings.output_dir)

    try:
        before, after = store.load(previous), store.load(current)
    except IncompatibleFindings as exc:
        _fail(str(exc))

    report_obj = compare(
        before,
        after,
        previous_snapshot_id=previous.stem,
        current_snapshot_id=current.stem,
    )
    summary = report_obj.summary()

    click.secho("Posture change since the previous assessment", bold=True)
    click.echo(f"  resolved     {summary['resolved']}")
    click.echo(f"  new          {summary['new']}")
    click.echo(f"  improved     {summary['improved']}")
    click.echo(f"  persisting   {summary['persisting']}")
    click.echo(f"  regressed    {summary['regressed']}")
    for finding in report_obj.open_in_both:
        change = report_obj.changes[finding.finding_id]
        if change.added or change.removed or change.unconfirmed:
            click.echo(
                f"    {finding.rule_id}: {change.previous_count} -> {change.current_count}"
                + (f"  fixed: {', '.join(change.removed)}" if change.removed else "")
                + (f"  added: {', '.join(change.added)}" if change.added else "")
                + (f"  not rechecked: {', '.join(change.unconfirmed)}" if change.unconfirmed else "")
            )
    if report_obj.not_revalidated or report_obj.first_assessed:
        click.secho(
            f"  not rechecked {summary['not_revalidated']}   first checked {summary['first_assessed']}"
            "  -- the two runs could not see the same checks; left out of resolved, new and risk",
            fg="yellow",
        )
        for finding in report_obj.not_revalidated:
            click.echo(f"    not rechecked: {finding.rule_id} {finding.title}")
    click.echo(f"  net change   {summary['net_change']:+d}")
    click.echo(
        f"  risk score   {summary['risk']['previous']} -> {summary['risk']['current']} "
        f"({summary['risk']['change']:+.2f})"
    )

    # Named after the current findings file (tenant__<snapshot>__delta.json), so
    # retention ages it with the findings it was built from. A file whose name
    # carries no date would be kept forever.
    out = file_in(settings.output_dir, f"{current.stem.removesuffix('__findings')}__delta.json")
    write_private(out, json.dumps(summary, indent=2))
    click.secho(f"Written: {out}", fg="green")


@cli.command(name="preflight-m365")
def preflight_m365() -> None:
    """Microsoft 365: sign in with the certificate and try one read per permission.

    Reads ICP_M365_TENANT_ID, ICP_M365_CLIENT_ID, ICP_M365_CERT_THUMBPRINT and
    ICP_M365_KEY_FILE. Prints counts and Microsoft's error codes only.
    """
    import os

    from icp.preflight_m365 import run
    from icp.security.graph_readonly import GraphError

    missing = [
        v
        for v in (
            "ICP_M365_TENANT_ID",
            "ICP_M365_CLIENT_ID",
            "ICP_M365_CERT_THUMBPRINT",
            "ICP_M365_KEY_FILE",
        )
        if not os.environ.get(v)
    ]
    if missing:
        _fail(f"Set {', '.join(missing)} in .env.")
    client = _m365_client()
    try:
        results = run(client)
    except GraphError as exc:  # sign-in itself failed
        _fail(f"Sign-in to Microsoft failed: {exc}. Check the certificate upload, thumbprint and IDs.")

    click.secho("Microsoft 365 preflight (one read per permission)", bold=True)
    for r in results:
        mark = click.style("OK  ", fg="green") if r.ok else click.style("FAIL", fg="red")
        click.echo(f"  [{mark}] {r.probe.permission:<52} {r.probe.what}: {r.detail}")
    verbs = sorted({c.method for c in client.calls})
    click.echo(
        f"  Graph requests: {len(client.calls)} ({', '.join(verbs)}); "
        f"sign-in requests: {client.auth_requests} (token only)"
    )
    if any(not r.ok for r in results):
        _fail("Some permissions are not working; see FAIL lines above.")
    click.secho("All permissions work.", fg="green")


@cli.command(name="collect-aws")
@click.option(
    "--prowler-output",
    "prowler_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Prowler's json-ocsf results file for one AWS account.",
)
@click.option(
    "--prowler-log",
    "log_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Prowler's log, to find reads AWS refused. Default: prowler.log next to the results.",
)
@click.option("--account-alias", default="", help="A name for the account, for the cover. Default: none.")
@click.option(
    "--keep-prowler-output",
    is_flag=True,
    help="Keep Prowler's unencrypted results file after import (default: delete it).",
)
@click.option(
    "--no-encrypt",
    is_flag=True,
    help="Write the snapshot unencrypted. Needs ICP_TEST_ENVIRONMENT=true (test accounts only).",
)
@click.pass_context
def collect_aws(
    ctx: click.Context,
    prowler_path: Path,
    log_path: Path | None,
    account_alias: str,
    keep_prowler_output: bool,
    no_encrypt: bool,
) -> None:
    """AWS: import Prowler's results for one account into a snapshot.

    Prowler reads the account (the `prowler` service, through the read-only
    role); this turns its results file into an encrypted snapshot like the
    other platforms'. This command makes no request to AWS. Tenant label for
    file names: ICP_AWS_TENANT_LABEL (default "aws").
    """
    import os

    from icp.collectors.aws import ProwlerImportError, import_prowler
    from icp.storage.snapshot_store import SnapshotStore

    settings = _settings(ctx)
    log_path = log_path or prowler_path.with_name("prowler.log")
    if not log_path.exists():
        click.secho(
            f"  no Prowler log at {log_path}: reads AWS refused cannot be detected, so the checks "
            "that depend on them will be reported as not assessed.",
            fg="yellow",
        )
    try:
        snapshot = import_prowler(
            prowler_path,
            tenant_id=os.environ.get("ICP_AWS_TENANT_LABEL", "aws"),
            account_alias=account_alias,
            log_path=log_path if log_path.exists() else None,
        )
    except ProwlerImportError as exc:
        _fail(str(exc))

    encrypt = _encrypt_live(settings, no_encrypt)
    try:
        path = SnapshotStore(settings.snapshot_dir, encrypt=encrypt).save(snapshot)
    except Exception as exc:
        _fail(f"{type(exc).__name__}: {exc}")

    prowler = snapshot.artifacts["aws.prowler"]
    rows = prowler["results"]
    click.secho(f"Snapshot written: {path}", fg="green")
    click.echo(
        f"  account: {snapshot.artifacts['aws.account']['account_id']}   Prowler {prowler['prowler_version']}   "
        f"results kept: {len(rows)} ({sum(1 for r in rows if r['status'] == 'FAIL')} failed) "
        f"from {len({r['check_id'] for r in rows})} of {len(prowler['checks_mapped'])} mapped checks"
    )
    for error in snapshot.errors:
        click.secho(f"  not assessed: {error.collector}: {error.message}", fg="yellow")
    for action, info in (snapshot.artifacts.get("aws.denied") or {}).items():
        why = (
            " by an organization policy (service control policy)" if info["by_organization_policy"] else ""
        )
        click.secho(f"  AWS refused {action}{why}: {info['count']} time(s)", fg="yellow")
    if snapshot.started_at:
        # Prowler stamps every result with the scan's start time.
        click.echo(
            f"  scan started (UTC): {snapshot.started_at:%Y-%m-%d %H:%M:%S}  -- filter CloudTrail from "
            "this time, for the assessment role"
        )
    # Prowler's file is unencrypted and lists every resource it read; the
    # snapshot now holds what the report needs, encrypted.
    if not keep_prowler_output:
        for leftover in (prowler_path, log_path):
            if leftover.exists():
                leftover.unlink()
                click.echo(f"  deleted Prowler's unencrypted file: {leftover.name}")


@cli.command(name="collect-m365")
@click.option(
    "--no-encrypt",
    is_flag=True,
    help="Write the snapshot unencrypted. Needs ICP_TEST_ENVIRONMENT=true (test tenants only).",
)
@click.pass_context
def collect_m365(ctx: click.Context, no_encrypt: bool) -> None:
    """Microsoft 365: read the tenant through Graph and write a snapshot.

    Same contract as `collect`: read-only, encrypted at rest, with a call
    trail to reconcile against the Entra audit log. Tenant label for file
    names: ICP_M365_TENANT_LABEL (default "m365").
    """
    import os

    from icp.collectors import microsoft as m365
    from icp.security.audit_log import write_audit_trail
    from icp.storage.snapshot_store import SnapshotStore

    settings = _settings(ctx)
    encrypt = _encrypt_live(settings, no_encrypt)  # before signing in: a refusal costs no read
    client = _m365_client()
    try:
        snapshot = m365.collect(client, tenant_id=os.environ.get("ICP_M365_TENANT_LABEL", "m365"))
    except Exception as exc:
        _fail(f"{type(exc).__name__}: {exc}")

    try:
        store = SnapshotStore(settings.snapshot_dir, encrypt=encrypt)
        path = store.save(snapshot)
        trail = write_audit_trail(
            store.trail_path_for(snapshot),
            list(snapshot.api_calls),
            tenant_id=snapshot.tenant_id,
        )
    except Exception as exc:
        _fail(f"{type(exc).__name__}: {exc}")

    click.echo(f"Read-only call trail: {trail}")
    click.secho(f"Snapshot written: {path}", fg="green")
    verbs = ", ".join(sorted({c.method for c in snapshot.api_calls}))
    click.echo(
        f"  artifacts: {len(snapshot.artifacts)}   Graph requests: {len(snapshot.api_calls)} ({verbs})"
        f"   sign-in requests: {client.auth_requests} (token only)"
    )
    if client.retries:
        click.echo(
            f"  repeated requests: {client.retries} (the same reads again, after a slow or busy response)"
        )
    if snapshot.started_at:
        click.echo(
            f"  collection window (UTC): {snapshot.started_at:%Y-%m-%d %H:%M:%S} to "
            f"{snapshot.collected_at:%H:%M:%S}  -- filter the Entra audit log to this"
        )
    if snapshot.errors:
        click.secho(f"  degraded collectors: {', '.join(snapshot.degraded_collectors())}", fg="yellow")
        for e in snapshot.errors:
            click.secho(f"    {e.collector}: {e.message}", fg="yellow")
    for name, reason in snapshot.partial.items():
        click.secho(f"  partial: {name}: {reason}", fg="yellow")


def _m365_client():  # type: ignore[no-untyped-def]
    import os

    from icp.security.credentials import CredentialError
    from icp.security.graph_readonly import GraphCredentials, GraphReadOnly

    needed = ("ICP_M365_TENANT_ID", "ICP_M365_CLIENT_ID", "ICP_M365_CERT_THUMBPRINT", "ICP_M365_KEY_FILE")
    missing = [v for v in needed if not os.environ.get(v)]
    if missing:
        _fail(f"Set {', '.join(missing)} in .env.")
    try:
        creds = GraphCredentials.from_files(
            tenant_id=os.environ["ICP_M365_TENANT_ID"],
            client_id=os.environ["ICP_M365_CLIENT_ID"],
            thumbprint=os.environ["ICP_M365_CERT_THUMBPRINT"],
            key_file=Path(os.environ["ICP_M365_KEY_FILE"]),
        )
    except OSError as exc:
        _fail(f"Cannot read the Microsoft 365 private key: {exc}")
    except CredentialError as exc:
        _fail(f"Microsoft 365 private key refused: {exc}")
    return GraphReadOnly(creds)


@cli.command(name="validate-delta")
@click.option(
    "--previous", required=True, type=click.Path(exists=True, path_type=Path), help="Earlier snapshot file."
)
@click.option(
    "--current", required=True, type=click.Path(exists=True, path_type=Path), help="Later snapshot file."
)
@click.pass_context
def validate_delta(ctx: click.Context, previous: Path, current: Path) -> None:
    """Re-derive a delta from its two snapshots and check it matches the saved one.

    Offline. Proves the saved findings files are exactly what the snapshots
    produce, so a before/after comparison shown to a client rests on the raw
    data, not on files that could be stale or edited.
    """
    from icp.delta.validate import validate
    from icp.storage.finding_store import FindingStore, IncompatibleFindings
    from icp.storage.snapshot_store import SnapshotStore

    settings = _settings(ctx)
    snapshots = SnapshotStore(settings.snapshot_dir, encrypt=False)
    findings = FindingStore(settings.output_dir)

    before, after = snapshots.load(previous), snapshots.load(current)
    saved = []
    for snap in (before, after):
        path = findings.path_for(snap.tenant_id, snap.snapshot_id)
        if not path.exists():
            _fail(f"No saved findings for snapshot {snap.snapshot_id}. Run: icp assess --snapshot <file>")
        try:
            saved.append(findings.load(path))
        except IncompatibleFindings as exc:
            _fail(str(exc))

    checks, summary = validate(before, after, saved[0], saved[1])

    click.secho(
        f"Validating delta {before.snapshot_id} -> {after.snapshot_id} from the snapshots", bold=True
    )
    for check in checks:
        mark = click.style("PASS", fg="green") if check.passed else click.style("FAIL", fg="red")
        click.echo(f"  [{mark}] {check.label}" + (f": {check.detail}" if check.detail else ""))
    click.echo(
        f"  resolved {summary['resolved']}  new {summary['new']}  improved {summary['improved']}  "
        f"regressed {summary['regressed']}  persisting {summary['persisting']}"
    )
    if not all(c.passed for c in checks):
        _fail("Delta validation failed: the saved findings do not match what the snapshots produce.")
    click.secho("All checks passed.", fg="green")


# -- fixtures ------------------------------------------------------------------


@cli.command(name="freeze-fixtures")
@click.option("--snapshot", "snapshot_path", type=click.Path(exists=True, path_type=Path))
@click.option("--tenant", help="Use the latest snapshot for this tenant.")
@click.option("--out", "out_dir", type=click.Path(path_type=Path), help="Default: <fixture dir>/google-dev")
@click.pass_context
def freeze_fixtures(
    ctx: click.Context, snapshot_path: Path | None, tenant: str | None, out_dir: Path | None
) -> None:
    """Freeze a snapshot into a pseudonymized offline fixture set.

    Dev tenants only. Emails, names, domains and IDs are replaced; if any
    survives, nothing is written.
    """
    from icp.storage.freeze import FreezeLeak, freeze
    from icp.storage.snapshot_store import SnapshotStore

    settings = _settings(ctx)
    store = SnapshotStore(settings.snapshot_dir, encrypt=False)
    snapshot = _load_snapshot(store, snapshot_path, tenant or settings.tenant_id)
    target = out_dir or settings.fixture_dir / "google-dev"

    try:
        result = freeze(snapshot, target)
    except FreezeLeak as exc:
        _fail(str(exc))
    except OSError as exc:
        _fail(f"{type(exc).__name__}: {exc}")

    click.secho(f"Froze {snapshot.snapshot_id} into {result.out_dir}", fg="green")
    click.echo(f"  files: {len(result.files)}   collected: {snapshot.collected_at:%Y-%m-%d %H:%M:%S} UTC")
    if snapshot.errors:
        click.echo(f"  degraded collectors kept as errors: {', '.join(snapshot.degraded_collectors())}")


# -- data handling -------------------------------------------------------------


@cli.command()
@click.option("--dry-run", is_flag=True, help="Show what would be deleted.")
@click.option("--operator", default="", help="Who performed the deletion, for the attestation.")
@click.pass_context
def purge(ctx: click.Context, dry_run: bool, operator: str) -> None:
    """Delete files past their retention period and write a deletion attestation.

    Each kind has its own period (data handling policy, section 4): snapshots
    ICP_RETENTION_DAYS, API call trails ICP_AUDIT_TRAIL_RETENTION_DAYS,
    findings and deltas ICP_FINDINGS_RETENTION_DAYS, reports
    ICP_REPORT_RETENTION_DAYS (unset: kept). The encryption key is not
    touched: destroy it in the secret manager when the engagement ends.
    """
    from icp.storage.finding_store import deletion_attestation
    from icp.storage.retention import KINDS
    from icp.storage.retention import purge as run_purge

    settings = _settings(ctx)
    try:
        retention = settings.retention()
    except ConfigError as exc:
        _fail(str(exc))
    folders = {"snapshots": settings.snapshot_dir, "output": settings.output_dir}
    result = run_purge(folders, retention, dry_run=dry_run)

    verb = "Would delete" if dry_run else "Deleted"
    for kind in KINDS:
        days = retention[kind.name]
        label = kind.name.replace("_", " ")
        if days is None:
            click.echo(f"  {label}: kept ({kind.setting} not set)")
        else:
            count = len(result.deleted.get(kind.name, []))
            click.echo(f"  {label}: {verb.lower()} {count} older than {days} days")
    for name, why in sorted(result.failed.items()):
        click.secho(f"  could not delete {name}: {why}", fg="red")

    if not result.count and not result.failed:
        click.echo("Nothing past its retention period.")
        return
    click.secho(f"{verb} {result.count} file(s).", fg="green")
    if not dry_run:
        attestation = deletion_attestation(
            settings.tenant_id,
            result.deleted,
            retention=retention,
            failed=result.failed,
            operator=operator,
        )
        # To the second: a second purge on the same day must not overwrite the first's record.
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = settings.output_dir / f"deletion-attestation-{stamp}.json"
        private_dir(path.parent)
        write_private(path, json.dumps(attestation, indent=2))
        click.secho(f"Attestation: {path}", fg="green")
    if result.failed:
        _fail(f"{len(result.failed)} file(s) could not be deleted; the attestation names them.")


@cli.command()
def keygen() -> None:
    """Generate a snapshot encryption key for ICP_SNAPSHOT_KEY."""
    from icp.security.crypto import generate_key

    click.echo(generate_key())
    click.secho(
        "Store this in a secret manager. Losing it makes existing snapshots unreadable.",
        fg="yellow",
        err=True,
    )


# -- introspection -------------------------------------------------------------


@cli.command()
@click.option("--offline", is_flag=True, help="Configuration checks only; contact nothing.")
@click.pass_context
def preflight(ctx: click.Context, offline: bool) -> None:
    """Verify credentials and delegation before a real collection run.

    Makes one minimal read per API surface and reports each independently, so a
    partial delegation grant tells you exactly which scope is missing instead of
    failing forty seconds into a collection.
    """
    from icp.preflight import check_api_access, check_configuration

    settings = _settings(ctx)

    click.secho("Configuration", bold=True)
    results = check_configuration(settings)
    _render(results)

    if any(not r.ok and r.probe.required for r in results):
        click.secho("\nFix the configuration above before probing the tenant.", fg="red", err=True)
        sys.exit(1)

    if offline:
        click.echo("\nOffline mode: no API calls made.")
        return

    click.secho("\nAPI access (read-only probes)", bold=True)
    try:
        api_results = check_api_access(settings)
    except Exception as exc:
        _fail(
            f"Could not authenticate: {type(exc).__name__}: {exc}\n"
            "       Check the service account key, and that domain-wide delegation has been "
            "granted for its client ID."
        )

    _render(api_results)

    required_failures = [r for r in api_results if not r.ok and r.probe.required]
    degraded = [r for r in api_results if not r.ok and not r.probe.required]

    click.echo()
    if required_failures:
        click.secho(
            f"{len(required_failures)} required surface(s) unreachable. "
            "Collection would produce an incomplete assessment.",
            fg="red",
            err=True,
        )
        sys.exit(1)

    if degraded:
        click.secho(
            f"Ready, with {len(degraded)} surface(s) degraded. Affected checks will appear "
            "as coverage notes in the report, never as passes.",
            fg="yellow",
        )
    else:
        click.secho("Ready. Every surface reachable, every call a read.", fg="green")


def _render(results: list) -> None:
    """One line per check, with the fix inline when it failed."""
    colours = {"OK": "green", "DEGRADED": "yellow", "FAIL": "red"}
    for result in results:
        click.echo(
            f"  [{click.style(result.status, fg=colours[result.status])}]"
            f"{' ' * max(1, 11 - len(result.status))}{result.probe.name}"
        )
        if not result.ok:
            for line in result.detail.splitlines():
                click.echo(f"           {line}")
            if result.probe.families:
                click.echo(f"           affects: {result.probe.families}")


@cli.command(name="list-rules")
def list_rules() -> None:
    """List every registered check."""
    from icp.reporting.remediation import RemediationLibrary
    from icp.rules import all_rules

    library = RemediationLibrary.load_default()
    click.echo(f"{'RULE':<16}{'FAMILY':<28}{'I/E':<6}TITLE")
    for rule_cls in sorted(all_rules(), key=lambda r: r.rule_id):
        marker = "" if rule_cls.remediation_key in library.entries else "  [no content!]"
        click.echo(
            f"{rule_cls.rule_id:<16}{rule_cls.check_family!s:<28}"
            f"{rule_cls.impact}/{rule_cls.exposure:<4}{rule_cls.title}{marker}"
        )


@cli.command(name="verify-scopes")
def verify_scopes() -> None:
    """Print the scope allowlist. Useful for the client prerequisites sheet."""
    from icp.security.scopes import assert_read_only, optional_scopes, sorted_scopes, write_capable

    core, optional = sorted_scopes(), optional_scopes()
    assert_read_only([*core, *optional])
    click.secho("Required (without these, collection cannot start):", bold=True)
    for scope in core:
        click.echo(f"  {scope}")
    click.secho("\nOptional (without these, only the named check is skipped):", bold=True)
    for scope in optional:
        click.echo(f"  {scope}")
    click.echo(
        "\nFor the domain-wide delegation entry, comma-separated:\n  " + ",".join([*core, *optional])
    )
    caveats = write_capable([*core, *optional])
    click.secho(
        f"\n{len(core) + len(optional)} scopes, all on the reviewed allowlist; "
        f"{len(core) + len(optional) - len(caveats)} are read-only scopes.",
        fg="green",
    )
    for scope, reason in caveats:
        click.echo(f"Not a read-only scope: {scope}\n  It is {reason}")
    click.echo("The tool sends read and list requests only; state-changing requests are blocked.")


#: Words that mean "nobody filled this in". Compared case-insensitively.
_PLACEHOLDER_NAMES = frozenset({"client", "client name", "assessor", "your name", "independent assessor"})


def _cover_name(value: str, what: str, flag: str, envvar: str) -> str:
    """Return a real name for the cover page, or stop with instructions."""
    name = (value or "").strip()
    if not name or name.lower() in _PLACEHOLDER_NAMES:
        shown = f" (got {name!r})" if name else ""
        _fail(
            f"No {what} for the report cover{shown}. Set {envvar} in .env, for example\n"
            f'       {envvar}="Riverside Community Trust"\n'
            f'       or pass {flag} "...".'
        )
    return name


def _client_override(value: str) -> str:
    """An explicit --client-name, checked; "" means "use what Google reports"."""
    name = (value or "").strip()
    if name and name.lower() in _PLACEHOLDER_NAMES:
        _fail(
            f"--client-name {name!r} is a placeholder, not a name. Pass the real name, or leave "
            "it out to use the organization name from the client's Google Workspace profile."
        )
    return name


def _client_name(override: str, tenant_view) -> str:  # type: ignore[no-untyped-def]
    """The cover's organization name: override, else Google's profile name, else domain."""
    from icp.reporting.platform_text import for_platform

    if override:
        click.echo(f"Cover name: {override} (from --client-name)")
        return override
    if tenant_view.organization_name:
        click.echo(
            f"Cover name: {tenant_view.organization_name} "
            f"(from {for_platform(tenant_view.platform).cover_name_source})"
        )
        return str(tenant_view.organization_name)
    if tenant_view.primary_domain:
        from icp.models.enums import Platform

        hint = {
            Platform.AWS: "pass --client-name, or --account-alias when importing with collect-aws",
            Platform.MICROSOFT_365: "pass --client-name",
        }.get(
            tenant_view.platform,
            "add admin.directory.customer.readonly to the domain-wide delegation entry and collect again",
        )
        click.secho(
            f"Cover name: {tenant_view.primary_domain} "
            + (
                "(the primary domain). "
                if tenant_view.platform == Platform.GOOGLE_WORKSPACE
                else "(no organization name in the snapshot). "
            )
            + f"To use the organization's name instead, {hint}.",
            fg="yellow",
        )
        return str(tenant_view.primary_domain)
    _fail(
        "Google returned neither the organization's name nor its primary domain for this "
        "snapshot, so the cover has no name. Check `icp preflight`, or pass --client-name."
    )
    return ""  # unreachable; _fail exits


def _latest_per_platform(store, settings, with_progress: bool):  # type: ignore[no-untyped-def]
    """The newest snapshot for each configured platform, and the one before it.

    By configured label only, so a sample or test snapshot saved under another
    label (aws-sample, say) is never picked up into a client's report. And
    only for a platform this engagement's settings set up: a Microsoft or AWS
    snapshot left from another engagement under the default label is not this
    client's. (The report then checks each snapshot's tenant or account.)
    """
    import os

    from icp.models.enums import Platform
    from icp.storage import identity

    labels = [
        ("Google Workspace", Platform.GOOGLE_WORKSPACE, settings.tenant_id),
        ("Microsoft 365", Platform.MICROSOFT_365, os.environ.get("ICP_M365_TENANT_LABEL", "m365")),
        ("AWS", Platform.AWS, os.environ.get("ICP_AWS_TENANT_LABEL", "aws")),
    ]
    current: list[Path] = []
    previous: list[Path] = []
    for name, platform, label in labels:
        if platform != Platform.GOOGLE_WORKSPACE and not identity.configured(platform):
            click.echo(f"  {name}: not configured in this engagement's settings, left out")
            continue
        found = store.list_snapshots(label) if label else []
        if not found:
            click.echo(f"  {name}: no snapshot (label {label or 'not set'}), left out")
            continue
        current.append(found[-1])
        note = ""
        if with_progress and len(found) > 1:
            previous.append(found[-2])
            note = f", compared with {found[-2].name}"
        click.echo(f"  {name}: {found[-1].name}{note}")
    if not current:
        _fail("No snapshots found for any configured platform. Collect first.")
    return tuple(current), tuple(previous)


def _check_identity(snapshot, path: Path | None) -> None:  # type: ignore[no-untyped-def]
    """Stop if the snapshot is of another tenant or account than this engagement's."""
    from icp.storage import identity

    name = path.name if path else snapshot.snapshot_id
    result = identity.check(snapshot)
    if result.expected and result.found and not result.matches:
        _fail(
            f"{name} is of {result.found}, but {result.setting} in this engagement's settings "
            f"names {result.expected}: it may be another client's snapshot, so no report was "
            "written. Keep each engagement in its own working copy (or ICP_SNAPSHOT_DIR) with "
            "its own ICP_SNAPSHOT_KEY."
        )
    elif result.expected and not result.found:
        click.secho(
            f"  {name}: holds no tenant or account identifier, so it cannot be checked against "
            f"{result.setting}. Confirm it is this client's before sending the report.",
            fg="yellow",
        )
    elif not result.expected:
        click.secho(
            f"  {name}: {result.found or 'no identifier'}; not checked, as {result.setting} is not set.",
            fg="yellow",
        )


def _check_age(snapshot, path: Path | None, max_age_days: int, allow_stale: bool) -> None:  # type: ignore[no-untyped-def]
    """Stop on a snapshot older than the limit, unless the assessor accepted that."""
    age = datetime.now(UTC) - snapshot.collected_at
    if age.days < max_age_days:
        return
    name = path.name if path else snapshot.snapshot_id
    when = f"{snapshot.collected_at:%Y-%m-%d}, {age.days} days ago"
    if not allow_stale:
        _fail(
            f"{name} was collected {when} (limit: {max_age_days} days, ICP_MAX_SNAPSHOT_AGE_DAYS). "
            "Collect again, or pass --allow-stale to report it as it was."
        )
    click.secho(f"  {name}: collected {when}; reported as it was (--allow-stale).", fg="yellow")


def _load_snapshot(store, snapshot_path: Path | None, tenant_id: str | None):  # type: ignore[no-untyped-def]
    if snapshot_path:
        return store.load(snapshot_path)
    if not tenant_id:
        _fail("Provide --snapshot or --tenant (or set ICP_TENANT_ID).")
    snapshot = store.load_latest(tenant_id)
    if snapshot is None:
        _fail(f"No snapshot found for tenant {tenant_id!r}. Run `icp collect` first.")
    return snapshot


def main() -> None:
    from icp.storage.paths import UnsafePathError

    try:
        cli(obj={})
    except UnsafePathError as exc:  # a crafted or corrupted snapshot: say so, no traceback
        _fail(str(exc))


if __name__ == "__main__":
    main()
