"""agentshield policies — policy management commands."""

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


@click.group("policies")
def policies_group() -> None:
    """Manage security policies."""


@policies_group.command("list")
@click.pass_context
def list_policies(ctx: click.Context) -> None:
    """List all security policies."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]
    try:
        policies = _api(server, api_key, "/api/policies/")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return

    if not policies:
        click.echo("No policies found.")
        return

    click.echo(f"\n{'ID':12} {'NAME':40} {'ACTION':12} {'SEVERITY':10} {'ENABLED':8} {'TRIGGERS':8}")
    click.echo("-" * 96)
    for p in policies:
        enabled_str = click.style("yes", fg="green") if p["is_enabled"] else click.style("no", fg="red")
        action_color = {"BLOCK": "red", "ALERT": "yellow", "LOG": "white", "RATE_LIMIT": "cyan"}.get(p["action"], "white")
        click.echo(
            f"{p['id'][:10]:12} "
            f"{p['name'][:38]:40} "
            f"{click.style(p['action']:12, fg=action_color)} "
            f"{p['severity']:10} "
            f"{enabled_str:8} "
            f"{p['trigger_count']:8}"
        )


@policies_group.command("create")
@click.option("--name", required=True, help="Policy name")
@click.option("--action", required=True, type=click.Choice(["BLOCK", "ALERT", "LOG", "RATE_LIMIT"]))
@click.option("--severity", default="medium", type=click.Choice(["low", "medium", "high", "critical"]))
@click.option("--condition", required=True, help="JSON condition string")
@click.pass_context
def create_policy(ctx: click.Context, name: str, action: str, severity: str, condition: str) -> None:
    """Create a new security policy."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]
    try:
        cond = json.loads(condition)
    except json.JSONDecodeError as e:
        click.echo(f"Invalid JSON condition: {e}", err=True)
        return
    try:
        result = _api(server, api_key, "/api/policies/", "POST", {
            "name": name, "action": action, "severity": severity, "condition": cond
        })
        click.echo(click.style(f"✓ Policy created: {result['id']}", fg="green"))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@policies_group.command("delete")
@click.argument("policy_id")
@click.confirmation_option(prompt="Delete this policy?")
@click.pass_context
def delete_policy(ctx: click.Context, policy_id: str) -> None:
    """Delete a policy."""
    server = ctx.obj["server"]
    api_key = ctx.obj["api_key"]
    try:
        req = urllib.request.Request(
            f"{server}/api/policies/{policy_id}",
            headers={"X-API-Key": api_key},
            method="DELETE",
        )
        urllib.request.urlopen(req, timeout=10)
        click.echo(click.style(f"✓ Policy {policy_id} deleted", fg="green"))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
