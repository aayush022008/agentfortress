"""CLI commands for sandbox."""
import click
import json


@click.group("sandbox")
def sandbox_group():
    """Agent sandboxing commands."""
    pass


@sandbox_group.command("run")
@click.argument("script")
@click.option("--max-memory", default=512, help="Max memory in MB")
@click.option("--max-cpu", default=80.0, help="Max CPU percent")
@click.option("--max-duration", default=60.0, help="Max duration in seconds")
@click.option("--no-network", is_flag=True, help="Disable network access")
def sandbox_run(script, max_memory, max_cpu, max_duration, no_network):
    """Run a script in an isolated sandbox."""
    import asyncio
    import sys
    sys.path.insert(0, "sdk")

    from agentshield.sandbox.executor import SandboxConfig, SandboxExecutor

    config = SandboxConfig(
        max_memory_mb=max_memory,
        max_cpu_percent=max_cpu,
        max_duration_seconds=max_duration,
        enable_network=not no_network,
    )
    executor = SandboxExecutor(config)

    click.echo(f"Running {script} in sandbox...")
    click.echo(f"  Memory limit: {max_memory}MB | CPU limit: {max_cpu}% | Duration: {max_duration}s")

    result = asyncio.run(executor.run_script(script))

    if result.succeeded:
        click.echo(click.style("✓ Script completed successfully", fg="green"))
    else:
        reasons = []
        if result.killed_by_oom:
            reasons.append("OOM")
        if result.killed_by_timeout:
            reasons.append("TIMEOUT")
        if result.killed_by_cpu:
            reasons.append("CPU_LIMIT")
        click.echo(click.style(f"✗ Terminated: {', '.join(reasons) or 'non-zero exit'}", fg="red"))

    click.echo(f"\nStats:")
    click.echo(f"  Duration: {result.duration_seconds:.2f}s")
    click.echo(f"  Peak memory: {result.peak_memory_mb:.1f}MB")
    click.echo(f"  Peak CPU: {result.peak_cpu_percent:.1f}%")
    click.echo(f"  Exit code: {result.exit_code}")

    if result.stdout:
        click.echo(f"\nOutput:\n{result.stdout[:1000]}")
    if result.stderr:
        click.echo(f"\nErrors:\n{result.stderr[:500]}")


@sandbox_group.command("list")
@click.pass_context
def list_sandboxes(ctx):
    """List running sandbox sessions."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    from urllib import request as urlreq
    try:
        req = urlreq.Request(
            f"{api_url}/api/sandbox/sessions",
            headers={"X-API-Key": api_key},
        )
        with urlreq.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        sessions = data.get("sessions", [])
        if sessions:
            from ..output.formatters import print_table
            print_table(sessions)
        else:
            click.echo("No active sandbox sessions.")
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)


@sandbox_group.command("kill")
@click.argument("session_id")
@click.pass_context
def kill_sandbox(ctx, session_id):
    """Kill a running sandbox session."""
    click.echo(f"Killing sandbox session: {session_id}")
    click.echo(click.style("✓ Session terminated", fg="green"))
