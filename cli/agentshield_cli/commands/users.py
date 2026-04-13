"""CLI commands for user management."""
import click
import json


@click.group("users")
def users_group():
    """User management commands."""
    pass


@users_group.command("list")
@click.option("--org-id", default=None, help="Filter by organization")
@click.pass_context
def list_users(ctx, org_id):
    """List platform users."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")
    from ..output.formatters import print_table

    url = f"{api_url}/api/users"
    if org_id:
        url += f"?org_id={org_id}"

    from urllib import request as urlreq
    try:
        req = urlreq.Request(url, headers={"X-API-Key": api_key})
        with urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        users = data.get("users", [])
        if users:
            print_table(users, columns=["user_id", "email", "roles", "created_at", "active"])
        else:
            click.echo("No users found.")
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)


@users_group.command("invite")
@click.argument("email")
@click.option("--role", default="viewer", help="Role to assign (admin|analyst|hunter|viewer)")
@click.option("--org-id", default=None, help="Organization ID")
@click.pass_context
def invite_user(ctx, email, role, org_id):
    """Invite a user to the platform."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    from urllib import request as urlreq
    payload = {"email": email, "role": role}
    if org_id:
        payload["org_id"] = org_id

    req = urlreq.Request(
        f"{api_url}/api/users/invite",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        click.echo(click.style(f"✓ Invitation sent to {email}", fg="green"))
        click.echo(f"  Role: {role}")
        if data.get("invite_link"):
            click.echo(f"  Link: {data['invite_link']}")
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)


@users_group.command("deactivate")
@click.argument("user_id")
@click.confirmation_option(prompt="Are you sure you want to deactivate this user?")
@click.pass_context
def deactivate_user(ctx, user_id):
    """Deactivate a user account."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    from urllib import request as urlreq
    req = urlreq.Request(
        f"{api_url}/api/users/{user_id}/deactivate",
        data=b"{}",
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urlreq.urlopen(req, timeout=10) as resp:
            click.echo(click.style(f"✓ User {user_id} deactivated", fg="green"))
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
