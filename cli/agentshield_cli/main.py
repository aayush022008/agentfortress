"""
AgentShield CLI — command line interface for developers.

Usage:
    agentshield init
    agentshield status
    agentshield alerts list
    agentshield sessions list
    agentshield policies list
    agentshield replay <session-id>
    agentshield scan <agent-file>
"""

import click

from .commands.init import init_cmd
from .commands.status import status_cmd
from .commands.alerts import alerts_group
from .commands.sessions import sessions_group
from .commands.policies import policies_group
from .commands.replay import replay_cmd
from .commands.scan import scan_cmd


@click.group()
@click.version_option(version="1.0.0", prog_name="agentshield")
@click.option(
    "--server",
    envvar="AGENTSHIELD_SERVER_URL",
    default="http://localhost:8000",
    help="AgentShield server URL",
    show_default=True,
)
@click.option(
    "--api-key",
    envvar="AGENTSHIELD_API_KEY",
    default="",
    help="API key for authentication",
)
@click.pass_context
def cli(ctx: click.Context, server: str, api_key: str) -> None:
    """AgentShield — Runtime protection for AI agents."""
    ctx.ensure_object(dict)
    ctx.obj["server"] = server
    ctx.obj["api_key"] = api_key


cli.add_command(init_cmd, "init")
cli.add_command(status_cmd, "status")
cli.add_command(alerts_group, "alerts")
cli.add_command(sessions_group, "sessions")
cli.add_command(policies_group, "policies")
cli.add_command(replay_cmd, "replay")
cli.add_command(scan_cmd, "scan")


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
