"""CLI commands for data export."""
import click
import json


@click.group("export")
def export_group():
    """Data export commands."""
    pass


def _do_export(ctx, resource: str, fmt: str, output: str, start_time=None, end_time=None, limit=None):
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")
    from ..output.spinner import Spinner

    payload = {"resource": resource, "format": fmt}
    if start_time:
        payload["start_time"] = start_time
    if end_time:
        payload["end_time"] = end_time
    if limit:
        payload["limit"] = limit

    with Spinner(f"Exporting {resource} as {fmt}..."):
        from urllib import request as urlreq
        req = urlreq.Request(
            f"{api_url}/api/export",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            click.echo(click.style(f"✓ Export queued: {data.get('export_id')}", fg="green"))
            click.echo(f"  Download: {data.get('download_url')}")
        except Exception as e:
            click.echo(click.style(f"Error: {e}", fg="red"), err=True)


@export_group.command("events")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "ndjson", "csv"]))
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--start-time", default=None, type=float)
@click.option("--end-time", default=None, type=float)
@click.option("--limit", default=None, type=int)
@click.pass_context
def export_events(ctx, fmt, output, start_time, end_time, limit):
    """Export agent events."""
    _do_export(ctx, "events", fmt, output, start_time, end_time, limit)


@export_group.command("alerts")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "ndjson", "csv"]))
@click.option("--output", "-o", default=None)
@click.option("--start-time", default=None, type=float)
@click.option("--end-time", default=None, type=float)
@click.pass_context
def export_alerts(ctx, fmt, output, start_time, end_time):
    """Export security alerts."""
    _do_export(ctx, "alerts", fmt, output, start_time, end_time)


@export_group.command("sessions")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "ndjson", "csv"]))
@click.option("--output", "-o", default=None)
@click.pass_context
def export_sessions(ctx, fmt, output):
    """Export agent sessions."""
    _do_export(ctx, "sessions", fmt, output)
