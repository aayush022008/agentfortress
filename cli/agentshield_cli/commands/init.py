"""agentshield init — interactive setup wizard."""

import json
import os

import click


CONFIG_PATH = os.path.expanduser("~/.agentshield/config.json")


@click.command("init")
@click.pass_context
def init_cmd(ctx: click.Context) -> None:
    """Interactive setup wizard for AgentShield."""
    click.echo(click.style("\n🛡️  AgentShield Setup Wizard\n", fg="cyan", bold=True))

    server = click.prompt(
        "AgentShield server URL",
        default="http://localhost:8000",
    )
    api_key = click.prompt("API Key (press Enter to skip)", default="", hide_input=True)
    environment = click.prompt(
        "Environment",
        type=click.Choice(["development", "staging", "production"]),
        default="development",
    )

    config = {
        "server_url": server,
        "api_key": api_key,
        "environment": environment,
    }

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

    click.echo(click.style(f"\n✅ Configuration saved to {CONFIG_PATH}", fg="green"))
    click.echo("\nQuick start:")
    click.echo(click.style("  import agentshield", fg="yellow"))
    click.echo(click.style(f'  agentshield.init(api_key="{api_key[:8]}...", server_url="{server}")', fg="yellow"))
    click.echo(click.style("  protected = agentshield.protect(my_agent)", fg="yellow"))
