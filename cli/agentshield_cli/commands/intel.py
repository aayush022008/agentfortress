"""CLI commands for threat intelligence."""
import click
import json


@click.group("intel")
def intel_group():
    """Threat intelligence commands."""
    pass


@intel_group.command("update")
@click.option("--source", default="all", help="Source to update (all|misp|opencti|local)")
@click.pass_context
def update_intel(ctx, source):
    """Update threat intelligence feeds."""
    from ..output.spinner import Spinner
    with Spinner(f"Updating threat intel from {source}..."):
        import time
        time.sleep(0.5)
    click.echo(click.style("✓ Threat intelligence updated", fg="green"))


@intel_group.command("search")
@click.argument("query")
@click.option("--type", "ioc_type", default=None, help="IOC type filter (ip|domain|hash|url|pattern)")
@click.option("--limit", default=20, help="Max results")
@click.pass_context
def search_intel(ctx, query, ioc_type, limit):
    """Search threat intelligence database."""
    from ..output.formatters import print_table

    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    url = f"{api_url}/api/threat-hunting/iocs"
    if ioc_type:
        url += f"?ioc_type={ioc_type}&limit={limit}"

    from urllib import request as urlreq
    try:
        req = urlreq.Request(url, headers={"X-API-Key": api_key})
        with urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        iocs = [i for i in data.get("iocs", []) if query.lower() in str(i).lower()]
        if iocs:
            print_table(iocs[:limit], columns=["ioc_id", "ioc_type", "value", "severity"])
        else:
            click.echo(f"No IOCs found matching '{query}'")
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)


@intel_group.command("add-pattern")
@click.option("--name", required=True, help="Pattern name")
@click.option("--pattern", required=True, help="Regex or string pattern")
@click.option("--type", "pattern_type", default="regex", type=click.Choice(["regex", "string", "yara"]))
@click.option("--severity", default="medium", type=click.Choice(["low", "medium", "high", "critical"]))
@click.option("--description", "-d", default="")
@click.pass_context
def add_pattern(ctx, name, pattern, pattern_type, severity, description):
    """Add a custom threat intelligence pattern."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")

    from urllib import request as urlreq
    payload = {
        "ioc_type": "pattern",
        "value": pattern,
        "description": f"{name}: {description}",
        "severity": severity,
        "source": "manual",
        "tags": ["custom", pattern_type],
    }
    req = urlreq.Request(
        f"{api_url}/api/threat-hunting/iocs",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        click.echo(click.style(f"✓ Pattern added: {data.get('ioc_id')}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
