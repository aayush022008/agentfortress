"""CLI commands for threat hunting."""
import click
import json
import sys


@click.group("hunt")
def hunt_group():
    """Threat hunting commands."""
    pass


@hunt_group.command("run")
@click.argument("query")
@click.option("--output", "-o", default="table", type=click.Choice(["table", "json", "csv"]))
@click.option("--limit", default=100, help="Max results to return")
@click.pass_context
def run_hunt(ctx, query: str, output: str, limit: int):
    """Execute an ad-hoc hunt query.

    QUERY is a SQL-like filter expression, e.g.:
      "SELECT * FROM events WHERE tool_name = 'bash'"
    """
    from ..output.spinner import Spinner
    from ..output.formatters import print_table, print_json

    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    with Spinner(f"Running hunt: {query[:60]}..."):
        from urllib import request as urlreq
        req = urlreq.Request(
            f"{api_url}/api/threat-hunting/query",
            data=json.dumps({"query": query}).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            click.echo(click.style(f"Error: {e}", fg="red"), err=True)
            sys.exit(1)

    results = data.get("results", [])
    click.echo(f"Found {len(results)} matches (total: {data.get('total', 0)})")

    if results:
        if output == "json":
            print_json(results)
        elif output == "csv":
            import csv, io
            buf = io.StringIO()
            if results:
                writer = csv.DictWriter(buf, fieldnames=list(results[0].keys()))
                writer.writeheader()
                writer.writerows(results)
            click.echo(buf.getvalue())
        else:
            print_table(results[:limit])


@hunt_group.command("list")
@click.pass_context
def list_hunts(ctx):
    """List all saved threat hunts."""
    from ..output.formatters import print_table
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    from urllib import request as urlreq
    req = urlreq.Request(
        f"{api_url}/api/threat-hunting/hunts",
        headers={"X-API-Key": api_key},
    )
    try:
        with urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        hunts = data.get("hunts", [])
        if hunts:
            print_table(hunts, columns=["hunt_id", "name", "schedule", "run_count", "last_run_at"])
        else:
            click.echo("No saved hunts found.")
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)


@hunt_group.command("save")
@click.argument("name")
@click.argument("query")
@click.option("--description", "-d", default="")
@click.option("--schedule", "-s", default=None, help="Cron schedule (e.g., @hourly, @daily)")
@click.pass_context
def save_hunt(ctx, name: str, query: str, description: str, schedule):
    """Save a threat hunt query."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    from urllib import request as urlreq
    payload = {"name": name, "query": query, "description": description}
    if schedule:
        payload["schedule"] = schedule

    req = urlreq.Request(
        f"{api_url}/api/threat-hunting/hunts",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        click.echo(click.style(f"✓ Hunt saved: {data.get('hunt_id')}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
