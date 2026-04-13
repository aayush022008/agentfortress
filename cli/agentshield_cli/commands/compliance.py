"""CLI commands for compliance."""
import click
import json


@click.group("compliance")
def compliance_group():
    """Compliance checking commands."""
    pass


@compliance_group.command("check")
@click.option("--frameworks", "-f", default="gdpr,hipaa,soc2", help="Comma-separated frameworks")
@click.option("--output", "-o", default="table", type=click.Choice(["table", "json"]))
@click.pass_context
def check_compliance(ctx, frameworks, output):
    """Run compliance checks across frameworks."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")
    from ..output.spinner import Spinner
    from ..output.formatters import print_table, print_json

    fw_list = [f.strip() for f in frameworks.split(",")]

    with Spinner(f"Running compliance checks: {frameworks}..."):
        from urllib import request as urlreq
        req = urlreq.Request(
            f"{api_url}/api/compliance/check",
            data=json.dumps({"frameworks": fw_list}).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            click.echo(click.style(f"Error: {e}", fg="red"), err=True)
            return

    results = data.get("results", {})
    if output == "json":
        print_json(results)
    else:
        rows = [
            {
                "framework": fw.upper(),
                "compliant": "✓" if r.get("compliant") else "✗",
                "score": f"{r.get('score', 0):.1f}%",
                "findings": len(r.get("findings", [])),
            }
            for fw, r in results.items()
        ]
        print_table(rows, columns=["framework", "compliant", "score", "findings"])


@compliance_group.command("report")
@click.option("--framework", "-f", required=True, help="Framework (gdpr|hipaa|soc2|eu_ai_act)")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "pdf"]))
@click.option("--output-dir", default=".", help="Directory to save report")
@click.pass_context
def generate_report(ctx, framework, fmt, output_dir):
    """Generate a compliance report."""
    cfg = ctx.obj or {}
    api_url = cfg.get("api_url", "http://localhost:8000")
    api_key = cfg.get("api_key", "")
    from ..output.spinner import Spinner

    with Spinner(f"Generating {framework.upper()} report..."):
        from urllib import request as urlreq
        req = urlreq.Request(
            f"{api_url}/api/compliance/report",
            data=json.dumps({"framework": framework, "format": fmt}).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
            click.echo(click.style(f"✓ Report queued: {data.get('report_id')}", fg="green"))
            click.echo(f"  Download: {data.get('download_url')}")
        except Exception as e:
            click.echo(click.style(f"Error: {e}", fg="red"), err=True)
