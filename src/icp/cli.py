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

logger = logging.getLogger("icp")


def _settings(ctx: click.Context) -> Settings:
    return ctx.obj["settings"]


def _fail(message: str) -> None:
    click.secho(f"error: {message}", fg="red", err=True)
    sys.exit(1)


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
@click.option("--no-encrypt", is_flag=True, help="Write plaintext. Dev tenants only.")
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

    encrypt = settings.encrypt_at_rest and not no_encrypt and not fixtures
    if not encrypt and not fixtures:
        click.secho(
            "warning: writing an unencrypted snapshot. Acceptable for a dev tenant only.",
            fg="yellow",
            err=True,
        )

    # Writing is as failure-prone as collecting -- a missing ICP_SNAPSHOT_KEY is
    # the single most common second-run mistake, and its exception already
    # carries the fix. Let the operator read it instead of a stack trace.
    try:
        store = SnapshotStore(settings.snapshot_dir, encrypt=encrypt)
        path = store.save(snapshot)

        if snapshot.api_calls:
            trail = write_audit_trail(
                settings.snapshot_dir / f"{snapshot.snapshot_id}.apicalls.jsonl",
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
@click.option("--snapshot", "snapshot_path", type=click.Path(exists=True, path_type=Path))
@click.option("--tenant", help="Use the latest snapshot for this tenant.")
@click.option(
    "--client-name",
    default="",
    help=(
        "Override the organization name on the cover. Default: the name in the client's "
        "Google Workspace account profile, or failing that its primary domain."
    ),
)
@click.option(
    "--assessor",
    envvar="ICP_ASSESSOR",
    default="",
    help="Your name or company, for the cover page. Default: $ICP_ASSESSOR.",
)
@click.option("--engagement-ref", default="", help="Reference from the authorization letter.")
@click.pass_context
def report(
    ctx: click.Context,
    snapshot_path: Path | None,
    tenant: str | None,
    client_name: str,
    assessor: str,
    engagement_ref: str,
) -> None:
    """Generate the client-facing report."""
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

    snapshot = _load_snapshot(store, snapshot_path, tenant or settings.tenant_id)
    tenant_view = normalize(snapshot)
    result = run_rules(tenant_view)
    client_name = _client_name(override, tenant_view)

    rendered = ReportRenderer().render(
        tenant_view,
        result,
        settings.output_dir,
        client_name=client_name,
        assessor=assessor,
        engagement_ref=engagement_ref,
    )

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
@click.option("--no-encrypt", is_flag=True)
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
    ctx.invoke(report, client_name=client_name, assessor=assessor)


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
        if change.added or change.removed:
            click.echo(
                f"    {finding.rule_id}: {change.previous_count} -> {change.current_count}"
                + (f"  fixed: {', '.join(change.removed)}" if change.removed else "")
                + (f"  added: {', '.join(change.added)}" if change.added else "")
            )
    click.echo(f"  net change   {summary['net_change']:+d}")
    click.echo(
        f"  risk score   {summary['risk']['previous']} -> {summary['risk']['current']} "
        f"({summary['risk']['change']:+.2f})"
    )

    out = settings.output_dir / "delta.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    click.secho(f"Written: {out}", fg="green")


@cli.command(name="preflight-m365")
def preflight_m365() -> None:
    """Microsoft 365: sign in with the certificate and try one read per permission.

    Reads ICP_M365_TENANT_ID, ICP_M365_CLIENT_ID, ICP_M365_CERT_THUMBPRINT and
    ICP_M365_KEY_FILE. Prints counts and Microsoft's error codes only.
    """
    import os

    from icp.preflight_m365 import run
    from icp.security.graph_readonly import GraphCredentials, GraphError, GraphReadOnly

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
    creds = GraphCredentials.from_files(
        tenant_id=os.environ["ICP_M365_TENANT_ID"],
        client_id=os.environ["ICP_M365_CLIENT_ID"],
        thumbprint=os.environ["ICP_M365_CERT_THUMBPRINT"],
        key_file=Path(os.environ["ICP_M365_KEY_FILE"]),
    )
    client = GraphReadOnly(creds)
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


@cli.command(name="collect-m365")
@click.option("--no-encrypt", is_flag=True, help="Write the snapshot unencrypted (dev tenants only).")
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
    client = _m365_client()
    try:
        snapshot = m365.collect(client, tenant_id=os.environ.get("ICP_M365_TENANT_LABEL", "m365"))
    except Exception as exc:
        _fail(f"{type(exc).__name__}: {exc}")

    encrypt = settings.encrypt_at_rest and not no_encrypt
    try:
        path = SnapshotStore(settings.snapshot_dir, encrypt=encrypt).save(snapshot)
        trail = write_audit_trail(
            settings.snapshot_dir / f"{snapshot.snapshot_id}.apicalls.jsonl",
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
    """Delete snapshots past the retention window and write a deletion attestation."""
    from icp.storage.finding_store import deletion_attestation
    from icp.storage.retention import purge as run_purge

    settings = _settings(ctx)
    deleted = run_purge(settings.snapshot_dir, settings.retention_days, dry_run=dry_run)

    if not deleted:
        click.echo(f"Nothing older than {settings.retention_days} days.")
        return

    click.secho(f"{'Would delete' if dry_run else 'Deleted'} {len(deleted)} file(s).", fg="green")
    if not dry_run:
        attestation = deletion_attestation(settings.tenant_id, deleted, operator=operator)
        stamp = datetime.now(UTC).strftime("%Y%m%d")
        path = settings.output_dir / f"deletion-attestation-{stamp}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(attestation, indent=2), encoding="utf-8")
        click.secho(f"Attestation: {path}", fg="green")


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
        click.secho(
            f"Cover name: {tenant_view.primary_domain} (the primary domain). To use the "
            "organization's name instead, add admin.directory.customer.readonly to the "
            "domain-wide delegation entry and collect again.",
            fg="yellow",
        )
        return str(tenant_view.primary_domain)
    _fail(
        "Google returned neither the organization's name nor its primary domain for this "
        "snapshot, so the cover has no name. Check `icp preflight`, or pass --client-name."
    )
    return ""  # unreachable; _fail exits


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
    cli(obj={})


if __name__ == "__main__":
    main()
