"""CLI commands for forensics."""
import click
import json
import sys


@click.group("forensics")
def forensics_group():
    """Forensics and incident response commands."""
    pass


@forensics_group.command("snapshot")
@click.option("--agent-id", required=True, help="Agent ID to snapshot")
@click.option("--session-id", required=True, help="Session ID")
@click.pass_context
def take_snapshot(ctx, agent_id, session_id):
    """Take an agent state snapshot."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")
    from ..output.spinner import Spinner

    with Spinner(f"Snapshotting agent {agent_id}..."):
        from urllib import request as urlreq
        payload = {"agent_id": agent_id, "session_id": session_id, "context": {}, "tool_state": {}}
        req = urlreq.Request(
            f"{api_url}/api/forensics/snapshots",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            click.echo(click.style(f"✓ Snapshot taken: {data.get('snapshot_id')}", fg="green"))
        except Exception as e:
            click.echo(click.style(f"Error: {e}", fg="red"), err=True)


@forensics_group.command("package")
@click.option("--case-id", default=None, help="Case ID (auto-generated if not set)")
@click.option("--investigator", default="", help="Investigator name")
@click.option("--description", "-d", default="")
@click.pass_context
def create_package(ctx, case_id, investigator, description):
    """Create an evidence package."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    from urllib import request as urlreq
    payload = {"investigator": investigator, "description": description}
    if case_id:
        payload["case_id"] = case_id

    req = urlreq.Request(
        f"{api_url}/api/forensics/evidence",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        click.echo(click.style(f"✓ Evidence package created: {data.get('case_id')}", fg="green"))
        click.echo(f"  Download: {data.get('download_url')}")
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)


@forensics_group.command("timeline")
@click.option("--incident-id", required=True, help="Incident ID")
@click.option("--start-time", default=None, type=float, help="Start timestamp")
@click.option("--end-time", default=None, type=float, help="End timestamp")
@click.pass_context
def build_timeline(ctx, incident_id, start_time, end_time):
    """Build an incident timeline."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")
    from ..output.spinner import Spinner
    from ..output.formatters import print_table

    payload = {"incident_id": incident_id}
    if start_time:
        payload["start_time"] = start_time
    if end_time:
        payload["end_time"] = end_time

    with Spinner(f"Building timeline for {incident_id}..."):
        from urllib import request as urlreq
        req = urlreq.Request(
            f"{api_url}/api/forensics/timeline",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            click.echo(f"\nTimeline: {data.get('incident_id')}")
            click.echo(f"Events: {len(data.get('events', []))}")
            click.echo(f"Summary:\n{data.get('summary', 'N/A')}")
        except Exception as e:
            click.echo(click.style(f"Error: {e}", fg="red"), err=True)
