"""
envleaks CLI entrypoint.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .scanner import scan_directory, scan_file
from .git_history import scan_git_history
from .reporters import terminal as term_reporter
from .reporters import json_report, sarif

console = Console()

SEVERITY_CHOICES = ["critical", "high", "medium", "low"]


def _parse_severities(ctx, param, value) -> list[str] | None:
    if not value:
        return None
    sevs = [s.strip().lower() for s in value.split(",")]
    for s in sevs:
        if s not in SEVERITY_CHOICES:
            raise click.BadParameter(f"'{s}' is not a valid severity. Choose from: {', '.join(SEVERITY_CHOICES)}")
    return sevs


@click.group()
@click.version_option(version="0.1.0", prog_name="envleaks")
def main():
    """
    \b
    envleaks — secret & credential scanner
    Scan codebases, git history, and Docker images for exposed secrets.

    \b
    Examples:
      envleaks scan .
      envleaks scan ./myproject --severity critical,high
      envleaks scan . --format json --output report.json
      envleaks scan . --git-history
      envleaks scan . --ci
      envleaks list-rules
    """
    pass


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", default="terminal",
              type=click.Choice(["terminal", "json", "sarif"]),
              help="Output format.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write output to file instead of stdout.")
@click.option("--severity", "-s", default=None, callback=_parse_severities,
              metavar="LEVELS",
              help="Comma-separated severity filter: critical,high,medium,low")
@click.option("--git-history", is_flag=True, default=False,
              help="Also scan all past git commits.")
@click.option("--max-commits", type=int, default=None,
              help="Limit number of commits to scan with --git-history.")
@click.option("--ci", is_flag=True, default=False,
              help="CI mode: exit code 1 if any findings, no banner.")
@click.option("--include", multiple=True, metavar="GLOB",
              help="Glob pattern(s) to include (e.g. '*.py').")
@click.option("--exclude", multiple=True, metavar="GLOB",
              help="Glob pattern(s) to exclude.")
def scan(path, fmt, output, severity, git_history, max_commits, ci, include, exclude):
    """Scan PATH for secrets and credentials."""

    if not ci:
        term_reporter.print_banner()

    include_list = list(include) if include else None
    exclude_list = list(exclude) if exclude else None

    # ── Scan filesystem ───────────────────────────────────────────────────────
    if path.is_file():
        with console.status("[dim]Scanning file...[/dim]"):
            result = scan_file(path, severity_filter=severity)
    else:
        with console.status(f"[dim]Scanning {path} ...[/dim]"):
            result = scan_directory(
                path,
                include_patterns=include_list,
                exclude_patterns=exclude_list,
                severity_filter=severity,
            )

    # ── Git history ───────────────────────────────────────────────────────────
    if git_history:
        git_result = None
        with Progress(
            SpinnerColumn(),
            TextColumn("[dim]{task.description}[/dim]"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning git history...", total=None)

            def on_progress(current, total, sha):
                progress.update(task, total=total, completed=current,
                                description=f"[dim]commit {sha}[/dim]")

            git_result = scan_git_history(
                path if path.is_dir() else path.parent,
                max_commits=max_commits,
                severity_filter=severity,
                progress_cb=on_progress,
            )

        # Merge results
        result.scanned_files += git_result.scanned_files
        result.skipped_files += git_result.skipped_files
        result.findings.extend(git_result.findings)

    # ── Output ────────────────────────────────────────────────────────────────
    root = path if path.is_dir() else path.parent

    if fmt == "terminal":
        if output:
            console.print(f"[yellow]Warning:[/yellow] --output ignored for terminal format.")
        term_reporter.print_results(result, root=root)

    elif fmt == "json":
        if output:
            json_report.write(result, output, root=root)
            console.print(f"[green]✓ JSON report written to {output}[/green]")
        else:
            json_report.print_json(result, root=root)

    elif fmt == "sarif":
        if not output:
            output = Path("envleaks.sarif")
        sarif.write(result, output, root=root)
        if not ci:
            console.print(f"[green]✓ SARIF report written to {output}[/green]")

    # ── CI exit code ──────────────────────────────────────────────────────────
    if ci and result.has_findings:
        console.print(
            f"[bold red]✗ envleaks found {len(result.findings)} secret(s). "
            "Pipeline blocked.[/bold red]"
        )
        sys.exit(1)


@main.command("list-rules")
@click.option("--severity", "-s", default=None, callback=_parse_severities,
              metavar="LEVELS", help="Filter by severity.")
def list_rules(severity):
    """List all built-in detection rules."""
    from rich.table import Table
    from rich import box
    from .patterns import PATTERNS, SEVERITY_COLORS

    table = Table(box=box.SIMPLE_HEAD, header_style="bold dim")
    table.add_column("ID", style="cyan", width=10)
    table.add_column("SEVERITY", width=12)
    table.add_column("NAME")
    table.add_column("DESCRIPTION")

    shown = [p for p in PATTERNS if severity is None or p.severity in severity]
    for p in shown:
        color = SEVERITY_COLORS.get(p.severity, "white")
        table.add_row(p.id, f"[{color}]{p.severity}[/{color}]", p.name, p.description)

    console.print(table)
    console.print(f"\n[dim]{len(shown)} rule(s) listed.[/dim]")
