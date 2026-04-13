"""agentshield alerts — alert management commands."""

import json
import urllib.request

import click


def _api(server: str, api_key: str, path: str, method: str = "GET", body: dict = None) -> dict:
    url = f"{server}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


SEVERITY_COLORS = {
    "critical": "red",
    "high": "yellow",
    "warning": "yellow",
    "info": "white",
}


@click.group("alerts")
def alerts_group() -> None:
    """Manage security alerts."""


@alerts_group.command("list")
@click.option("--severity", help="Filter by severity")
@click.option("--status", default="open", help="Filter by status", show_default=True)
@click.option("--limit", default=20, help="Max results", show_default=True)
@click.pass_context
def list_alerts(ctx: click.Context, severity: str, status: str, limit: int) -> None:
    """List security alerts."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]

    params = f"?limit={limit}&status={status}"
    if severity:
        params += f"&severity={severity}"

    try:
        alerts = _api(server, api_key, f"/api/alerts/{params}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return

    if not alerts:
        click.echo("No alerts found.")
        return

    click.echo(f"\n{'ID':12} {'SEVERITY':10} {'TYPE':25} {'TITLE':50} {'STATUS':12}")
    click.echo("-" * 115)
    for a in alerts:
        color = SEVERITY_COLORS.get(a["severity"], "white")
        click.echo(
            f"{a['id'][:10]:12} "
            f"{click.style(a['severity'].upper():10, fg=color)} "
            f"{a['alert_type']:25} "
            f"{a['title'][:48]:50} "
            f"{a['status']:12}"
        )


@alerts_group.command("ack")
@click.argument("alert_id")
@click.option("--by", default="cli-user", help="Who is acknowledging")
@click.pass_context
def ack_alert(ctx: click.Context, alert_id: str, by: str) -> None:
    """Acknowledge an alert."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]
    try:
        result = _api(server, api_key, f"/api/alerts/{alert_id}/acknowledge", "POST", {"acknowledged_by": by})
        click.echo(click.style(f"✓ Alert {alert_id} acknowledged", fg="green"))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@alerts_group.command("resolve")
@click.argument("alert_id")
@click.option("--by", default="cli-user", help="Who is resolving")
@click.pass_context
def resolve_alert(ctx: click.Context, alert_id: str, by: str) -> None:
    """Resolve an alert."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]
    try:
        _api(server, api_key, f"/api/alerts/{alert_id}/resolve", "POST", {"resolved_by": by})
        click.echo(click.style(f"✓ Alert {alert_id} resolved", fg="green"))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
