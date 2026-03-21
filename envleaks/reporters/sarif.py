"""
SARIF 2.1.0 reporter — compatible with GitHub Advanced Security code scanning.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..patterns import PATTERNS
from ..scanner import ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def to_sarif(result: ScanResult, root: Path | None = None) -> dict:
    rules = [
        {
            "id": p.id,
            "name": p.name.replace(" ", ""),
            "shortDescription": {"text": p.name},
            "fullDescription": {"text": p.description},
            "defaultConfiguration": {
                "level": SEVERITY_TO_LEVEL.get(p.severity, "warning")
            },
            "properties": {"tags": ["security", "secret-detection"], "severity": p.severity},
        }
        for p in PATTERNS
    ]

    results = []
    for f in result.findings:
        file_str = str(f.file)
        if root:
            try:
                file_str = str(Path(f.file).relative_to(root))
            except ValueError:
                pass

        results.append({
            "ruleId": f.pattern.id,
            "level": SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {
                "text": f"{f.pattern.name} detected. Match: {f.match}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_str.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_number,
                        },
                    }
                }
            ],
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "envleaks",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/ExploitCraft/envleaks",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write(result: ScanResult, output_path: Path, root: Path | None = None):
    data = to_sarif(result, root)
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
