"""agentshield replay — session replay in terminal."""

import json
import urllib.request
from datetime import datetime

import click


@click.command("replay")
@click.argument("session_id")
@click.option("--output", "-o", help="Save replay to JSON file")
@click.pass_context
def replay_cmd(ctx: click.Context, session_id: str, output: str) -> None:
    """Replay the complete timeline of an agent session."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]

    try:
        req = urllib.request.Request(
            f"{server}/api/replay/{session_id}",
            headers={"X-API-Key": api_key},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            replay = json.loads(resp.read())
    except Exception as e:
        click.echo(f"Error fetching replay: {e}", err=True)
        return

    if output:
        with open(output, "w") as f:
            json.dump(replay, f, indent=2)
        click.echo(click.style(f"✓ Replay saved to {output}", fg="green"))
        return

    # Print timeline in terminal
    click.echo(click.style(f"\n📼 Session Replay: {session_id}\n", bold=True, fg="cyan"))
    click.echo(f"  Agent:      {replay.get('agent_name', '?')}")
    click.echo(f"  Status:     {replay.get('status', '?')}")
    click.echo(f"  Duration:   {replay.get('duration_ms', 0):.0f}ms")
    click.echo(f"  Events:     {replay.get('total_events', 0)}")
    click.echo(f"  LLM calls:  {replay.get('total_llm_calls', 0)}")
    click.echo(f"  Tool calls: {replay.get('total_tool_calls', 0)}")
    max_score = replay.get("max_threat_score", 0)
    score_color = "red" if max_score >= 75 else "yellow" if max_score >= 40 else "green"
    click.echo(f"  Max threat: {click.style(str(max_score), fg=score_color)}")
    click.echo()

    for event in replay.get("events", []):
        t_ms = event.get("relative_time_ms", 0)
        etype = event.get("event_type", "?")
        score = event.get("threat_score", 0)
        blocked = event.get("blocked", False)

        type_color = {
            "llm_start": "blue", "llm_end": "cyan",
            "tool_start": "magenta", "tool_end": "white",
            "agent_start": "green", "agent_end": "green",
        }.get(etype, "white")

        prefix = "🔴 BLOCKED" if blocked else ("⚠️ " if score >= 50 else "  ")
        click.echo(
            f"  [{t_ms:8.1f}ms] {prefix} "
            f"{click.style(etype:20, fg=type_color)} "
            f"score={score}"
        )
        if blocked and event.get("threat_reasons"):
            for reason in event["threat_reasons"][:2]:
                click.echo(f"              → {reason}")
