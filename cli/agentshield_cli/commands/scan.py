"""agentshield scan — static analysis of agent code files."""

import ast
import re
import sys
from pathlib import Path
from typing import Any

import click


DANGEROUS_IMPORTS = {
    "os", "subprocess", "sys", "shutil", "pathlib",
    "socket", "urllib", "requests", "httpx", "aiohttp",
    "pickle", "marshal", "shelve", "exec", "eval",
}

DANGEROUS_CALLS = {
    "exec", "eval", "compile", "__import__",
    "os.system", "subprocess.run", "subprocess.call",
    "subprocess.Popen", "open",
}

PROMPT_INJECTION_INDICATORS = [
    r"ignore.{0,20}previous.{0,20}instructions",
    r"disregard.{0,20}system",
    r"jailbreak",
    r"DAN\b",
]


class AgentScanner(ast.NodeVisitor):
    """AST scanner for detecting potential security issues in agent code."""

    def __init__(self) -> None:
        self.findings: list[dict] = []
        self.imports: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
            if alias.name in DANGEROUS_IMPORTS:
                self.findings.append({
                    "line": node.lineno,
                    "severity": "medium",
                    "type": "dangerous_import",
                    "message": f"Imported potentially dangerous module: {alias.name}",
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in DANGEROUS_IMPORTS:
            self.findings.append({
                "line": node.lineno,
                "severity": "medium",
                "type": "dangerous_import",
                "message": f"Imported from potentially dangerous module: {node.module}",
            })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = f"{ast.unparse(node.func.value)}.{node.func.attr}"

        if call_name in DANGEROUS_CALLS:
            self.findings.append({
                "line": node.lineno,
                "severity": "high",
                "type": "dangerous_call",
                "message": f"Potentially dangerous function call: {call_name}()",
            })
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.s, str):
            for pattern in PROMPT_INJECTION_INDICATORS:
                if re.search(pattern, node.s, re.IGNORECASE):
                    self.findings.append({
                        "line": node.lineno,
                        "severity": "critical",
                        "type": "embedded_prompt_injection",
                        "message": f"Possible prompt injection pattern in string literal",
                    })
                    break
        self.generic_visit(node)


@click.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
def scan_cmd(ctx: click.Context, path: str, output: str) -> None:
    """Scan an agent file or directory for security issues."""
    import json as json_mod

    target = Path(path)
    files = list(target.rglob("*.py")) if target.is_dir() else [target]

    all_findings: list[dict] = []
    total_files = 0

    for pyfile in files:
        if any(part.startswith(".") for part in pyfile.parts):
            continue
        try:
            source = pyfile.read_text(encoding="utf-8")
            tree = ast.parse(source)
            scanner = AgentScanner()
            scanner.visit(tree)
            for f in scanner.findings:
                f["file"] = str(pyfile)
                all_findings.append(f)
            total_files += 1
        except SyntaxError as e:
            click.echo(f"Syntax error in {pyfile}: {e}", err=True)

    if output == "json":
        click.echo(json_mod.dumps({"files_scanned": total_files, "findings": all_findings}, indent=2))
        return

    click.echo(click.style(f"\n🔍 AgentShield Static Scan\n", bold=True, fg="cyan"))
    click.echo(f"  Files scanned: {total_files}")
    click.echo(f"  Findings:      {len(all_findings)}\n")

    if not all_findings:
        click.echo(click.style("  ✅ No issues found!", fg="green"))
        return

    severity_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "white"}

    for finding in sorted(all_findings, key=lambda f: f["line"]):
        sev = finding["severity"]
        color = severity_colors.get(sev, "white")
        click.echo(
            f"  {click.style(sev.upper():8, fg=color)} "
            f"{finding['file']}:{finding['line']} "
            f"[{finding['type']}]"
        )
        click.echo(f"           {finding['message']}")

    critical_count = sum(1 for f in all_findings if f["severity"] == "critical")
    if critical_count:
        click.echo(click.style(f"\n⛔ {critical_count} critical findings require immediate attention!", fg="red", bold=True))
        sys.exit(1)
