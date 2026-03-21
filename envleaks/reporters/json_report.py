"""
JSON reporter.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..scanner import ScanResult


def to_dict(result: ScanResult, root: Path | None = None) -> dict:
    findings = []
    for f in result.findings:
        file_str = str(f.file)
        if root:
            try:
                file_str = str(Path(f.file).relative_to(root))
            except ValueError:
                pass
        findings.append({
            "rule_id": f.pattern.id,
            "rule_name": f.pattern.name,
            "severity": f.severity,
            "file": file_str,
            "line": f.line_number,
            "match": f.match,
            "description": f.pattern.description,
        })

    return {
        "summary": {
            "scanned_files": result.scanned_files,
            "skipped_files": result.skipped_files,
            "total_findings": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
        },
        "findings": findings,
    }


def write(result: ScanResult, output_path: Path, root: Path | None = None):
    data = to_dict(result, root)
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def print_json(result: ScanResult, root: Path | None = None):
    import click
    data = to_dict(result, root)
    click.echo(json.dumps(data, indent=2))
