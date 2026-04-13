"""CLI commands for configuration management."""
import click
import json
import os
from pathlib import Path

CONFIG_PATH = Path.home() / ".agentshield" / "config.json"


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            return {}
    return {}


def save_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2))
    CONFIG_PATH.chmod(0o600)


@click.group("config")
def config_group():
    """Configuration management commands."""
    pass


@config_group.command("get")
@click.argument("key")
def config_get(key: str):
    """Get a configuration value."""
    config = load_config()
    value = config.get(key)
    if value is None:
        click.echo(click.style(f"Key '{key}' not found", fg="yellow"))
    else:
        click.echo(f"{key} = {value}")


@config_group.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """Set a configuration value."""
    config = load_config()
    config[key] = value
    save_config(config)
    click.echo(click.style(f"✓ Set {key} = {value}", fg="green"))


@config_group.command("list")
def config_list():
    """List all configuration values."""
    config = load_config()
    if not config:
        click.echo("No configuration set. Run 'agentshield init' to get started.")
        return
    for key, value in sorted(config.items()):
        # Mask sensitive values
        if any(s in key.lower() for s in ["key", "token", "secret", "password"]):
            display_value = value[:4] + "***" if len(str(value)) > 4 else "***"
        else:
            display_value = str(value)
        click.echo(f"  {key} = {display_value}")


@config_group.command("reset")
@click.confirmation_option(prompt="Are you sure you want to reset all configuration?")
def config_reset():
    """Reset all configuration to defaults."""
    if CONFIG_PATH.exists():
        CONFIG_PATH.unlink()
    click.echo(click.style("✓ Configuration reset", fg="green"))
