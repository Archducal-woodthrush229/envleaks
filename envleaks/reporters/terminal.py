"""
Rich terminal reporter.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from ..patterns import SEVERITY_COLORS
from ..scanner import ScanResult, Finding

console = Console(highlight=False)

SEVERITY_EMOJI = {
    "critical": "💀",
    "high":     "🔴",
    "medium":   "🟡",
    "low":      "🔵",
}


def _severity_text(sev: str) -> Text:
    color = SEVERITY_COLORS.get(sev, "white")
    label = f"{SEVERITY_EMOJI.get(sev, '')} {sev.upper()}"
    return Text(label, style=color)


def print_banner():
    console.print(Panel.fit(
        "[bold green]envleaks[/bold green] [dim]— secret & credential scanner[/dim]",
        border_style="green",
    ))


def print_results(result: ScanResult, root: Path | None = None):
    if not result.has_findings:
        console.print("\n[bold green]✓ No secrets found![/bold green]\n")
        _print_summary(result)
        return

    # Group findings by file
    by_file: dict[str, list[Finding]] = {}
    for f in result.findings:
        key = str(f.file)
        by_file.setdefault(key, []).append(f)

    console.print()
    for file_path, findings in by_file.items():
        rel = file_path
        if root:
            try:
                rel = str(Path(file_path).relative_to(root))
            except ValueError:
                pass

        console.print(f"[bold white]📄 {rel}[/bold white]")

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="dim",
            padding=(0, 1),
            expand=True,
        )
        table.add_column("LINE", style="dim", width=6, justify="right")
        table.add_column("SEVERITY", width=16)
        table.add_column("RULE", width=8, style="dim cyan")
        table.add_column("NAME", width=28)
        table.add_column("MATCH", style="yellow")

        for finding in findings:
            table.add_row(
                str(finding.line_number),
                _severity_text(finding.severity),
                finding.pattern.id,
                finding.pattern.name,
                finding.match,
            )

        console.print(table)

    _print_summary(result)


def _print_summary(result: ScanResult):
    table = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column(justify="right")

    table.add_row("Files scanned", str(result.scanned_files))
    table.add_row("Files skipped", str(result.skipped_files))
    table.add_row("Total findings", str(len(result.findings)))

    if result.has_findings:
        table.add_row("[bold red]Critical[/bold red]", f"[bold red]{result.critical_count}[/bold red]")
        table.add_row("[red]High[/red]", f"[red]{result.high_count}[/red]")
        table.add_row("[yellow]Medium[/yellow]", f"[yellow]{result.medium_count}[/yellow]")
        table.add_row("[cyan]Low[/cyan]", f"[cyan]{result.low_count}[/cyan]")

    console.print(Panel(table, title="[bold]Scan Summary[/bold]", border_style="dim"))
