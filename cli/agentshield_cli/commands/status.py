"""agentshield status — server health and active agents."""

import click
import urllib.request
import json


def _get(url: str, api_key: str) -> dict:
    req = urllib.request.Request(url, headers={"X-API-Key": api_key})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


@click.command("status")
@click.pass_context
def status_cmd(ctx: click.Context) -> None:
    """Show server health and active agent status."""
    server = ctx.obj.get("server", "http://localhost:8000")
    api_key = ctx.obj.get("api_key", "")

    click.echo(click.style("AgentShield Status\n", fg="cyan", bold=True))

    # Health check
    try:
        health = _get(f"{server}/health", api_key)
        click.echo(f"  Server:  {click.style('● online', fg='green')} — {server}")
        click.echo(f"  Version: {health.get('version', '?')}")
    except Exception as e:
        click.echo(f"  Server:  {click.style('● offline', fg='red')} — {e}")
        return

    # Stats
    try:
        stats = _get(f"{server}/api/analytics/overview", api_key)
        click.echo(f"\n  Active sessions:  {stats.get('active_sessions', 0)}")
        click.echo(f"  Total events:     {stats.get('total_events', 0)}")
        click.echo(f"  Open alerts:      {stats.get('open_alerts', 0)}")
        critical = stats.get("critical_alerts", 0)
        if critical > 0:
            click.echo(f"  Critical alerts:  {click.style(str(critical), fg='red', bold=True)}")
        click.echo(f"  Blocked events:   {stats.get('blocked_events', 0)}")
    except Exception as e:
        click.echo(f"  Could not fetch stats: {e}")
