"""Rich terminal output formatters."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def print_table(
    data: List[Dict[str, Any]],
    columns: Optional[List[str]] = None,
    max_col_width: int = 40,
) -> None:
    """Print data as a formatted ASCII table using rich if available."""
    try:
        from rich.table import Table
        from rich.console import Console

        console = Console()
        table = Table(show_header=True, header_style="bold cyan")

        if not data:
            console.print("[dim]No data[/dim]")
            return

        cols = columns or list(data[0].keys())
        for col in cols:
            table.add_column(col, max_width=max_col_width)

        for row in data:
            table.add_row(*[str(row.get(c, ""))[:max_col_width] for c in cols])

        console.print(table)

    except ImportError:
        # Fallback: plain text
        if not data:
            print("No data")
            return
        cols = columns or list(data[0].keys())
        widths = {c: max(len(c), max(len(str(row.get(c, ""))) for row in data)) for c in cols}
        widths = {c: min(w, max_col_width) for c, w in widths.items()}

        header = " | ".join(c.ljust(widths[c]) for c in cols)
        print(header)
        print("-" * len(header))
        for row in data:
            print(" | ".join(str(row.get(c, ""))[:widths[c]].ljust(widths[c]) for c in cols))


def print_json(data: Any, indent: int = 2) -> None:
    """Print data as colored JSON."""
    try:
        from rich.console import Console
        from rich.syntax import Syntax
        console = Console()
        text = json.dumps(data, indent=indent, default=str)
        console.print(Syntax(text, "json"))
    except ImportError:
        print(json.dumps(data, indent=indent, default=str))


def print_success(message: str) -> None:
    """Print a success message in green."""
    try:
        from rich.console import Console
        Console().print(f"[green]✓ {message}[/green]")
    except ImportError:
        print(f"✓ {message}")


def print_error(message: str) -> None:
    """Print an error message in red."""
    try:
        from rich.console import Console
        Console().print(f"[red]✗ {message}[/red]")
    except ImportError:
        print(f"✗ {message}")


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    try:
        from rich.console import Console
        Console().print(f"[yellow]⚠ {message}[/yellow]")
    except ImportError:
        print(f"⚠ {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    try:
        from rich.console import Console
        Console().print(f"[cyan]ℹ {message}[/cyan]")
    except ImportError:
        print(f"ℹ {message}")


def format_severity(severity: str) -> str:
    """Return colored severity string."""
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "cyan",
    }
    try:
        from rich.text import Text
        color = colors.get(severity.lower(), "white")
        return f"[{color}]{severity.upper()}[/{color}]"
    except ImportError:
        return severity.upper()


def print_progress_bar(current: int, total: int, width: int = 40) -> str:
    """Return a text progress bar string."""
    pct = current / max(total, 1)
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {current}/{total} ({pct:.0%})"
