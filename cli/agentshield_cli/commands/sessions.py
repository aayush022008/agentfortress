"""agentshield sessions — session management commands."""

import json
import urllib.request

import click


def _api(server: str, api_key: str, path: str, method: str = "GET", body: dict = None) -> any:
    url = f"{server}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url, data=data,
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


@click.group("sessions")
def sessions_group() -> None:
    """Manage agent sessions."""


@sessions_group.command("list")
@click.option("--status", help="Filter by status (active/completed/blocked/killed)")
@click.option("--limit", default=20, show_default=True)
@click.pass_context
def list_sessions(ctx: click.Context, status: str, limit: int) -> None:
    """List agent sessions."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]
    params = f"?limit={limit}"
    if status:
        params += f"&status={status}"
    try:
        sessions = _api(server, api_key, f"/api/sessions/{params}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return

    if not sessions:
        click.echo("No sessions found.")
        return

    click.echo(f"\n{'ID':36} {'AGENT':25} {'STATUS':12} {'EVENTS':8} {'THREATS':8} {'VIOLATIONS':10}")
    click.echo("-" * 105)
    for s in sessions:
        status_color = {"active": "green", "blocked": "red", "killed": "red"}.get(s["status"], "white")
        click.echo(
            f"{s['id']:36} "
            f"{s['agent_name'][:23]:25} "
            f"{click.style(s['status']:12, fg=status_color)} "
            f"{s['total_events']:8} "
            f"{s['max_threat_score']:8} "
            f"{s['violation_count']:10}"
        )


@sessions_group.command("inspect")
@click.argument("session_id")
@click.pass_context
def inspect_session(ctx: click.Context, session_id: str) -> None:
    """Inspect a specific session in detail."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]
    try:
        session = _api(server, api_key, f"/api/sessions/{session_id}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return

    click.echo(click.style(f"\nSession: {session_id}\n", bold=True))
    for k, v in session.items():
        click.echo(f"  {k:25}: {v}")


@sessions_group.command("kill")
@click.argument("session_id")
@click.confirmation_option(prompt="Are you sure you want to kill this session?")
@click.pass_context
def kill_session(ctx: click.Context, session_id: str) -> None:
    """Activate kill switch for a session."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]
    try:
        _api(server, api_key, f"/api/sessions/{session_id}/kill", "POST")
        click.echo(click.style(f"✓ Session {session_id} killed", fg="red", bold=True))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
