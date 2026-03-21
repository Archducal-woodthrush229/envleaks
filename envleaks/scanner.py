"""
Core file scanner — walks a directory, scans each file against all patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .patterns import PATTERNS, Pattern, SEVERITY_ORDER

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__",
    ".tox", ".venv", "venv", "env", ".env", "dist", "build",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "site-packages",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".pdf", ".zip", ".tar",
    ".gz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".bin", ".dll",
    ".so", ".dylib", ".pyc", ".pyo", ".whl", ".lock",
}

MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB


@dataclass
class Finding:
    pattern: Pattern
    file: Path
    line_number: int
    line_content: str
    match: str

    @property
    def severity(self) -> str:
        return self.pattern.severity

    @property
    def sort_key(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class ScanResult:
    scanned_files: int = 0
    skipped_files: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")


def _should_skip_file(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    try:
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return True
    except OSError:
        return True
    return False


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(".")


def _scan_content(
    content: str,
    file_path: Path,
    compiled: list[tuple[Pattern, re.Pattern]],
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    for line_no, line in enumerate(content.splitlines(), start=1):
        for pattern, regex in compiled:
            for m in regex.finditer(line):
                key = (pattern.id, line_no, m.group(0))
                if key in seen:
                    continue
                seen.add(key)
                match_str = m.group(0)
                redacted = match_str[:6] + "..." + match_str[-4:] if len(match_str) > 12 else match_str
                findings.append(Finding(
                    pattern=pattern,
                    file=file_path,
                    line_number=line_no,
                    line_content=line.strip()[:120],
                    match=redacted,
                ))
    return findings


def scan_directory(
    root: Path,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    severity_filter: list[str] | None = None,
) -> ScanResult:
    """Scan a directory tree for secrets."""
    result = ScanResult()

    active_patterns = [
        p for p in PATTERNS
        if severity_filter is None or p.severity in severity_filter
    ]
    compiled = [(p, p.compile()) for p in active_patterns]

    for path in _walk(root):
        if _should_skip_file(path):
            result.skipped_files += 1
            continue

        if include_patterns and not any(
            path.match(pat) for pat in include_patterns
        ):
            result.skipped_files += 1
            continue

        if exclude_patterns and any(
            path.match(pat) for pat in exclude_patterns
        ):
            result.skipped_files += 1
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result.skipped_files += 1
            continue

        result.scanned_files += 1
        result.findings.extend(_scan_content(content, path, compiled))

    result.findings.sort(key=lambda f: (f.sort_key, str(f.file), f.line_number))
    return result


def scan_file(path: Path, severity_filter: list[str] | None = None) -> ScanResult:
    """Scan a single file."""
    result = ScanResult()
    active_patterns = [
        p for p in PATTERNS
        if severity_filter is None or p.severity in severity_filter
    ]
    compiled = [(p, p.compile()) for p in active_patterns]

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        result.scanned_files = 1
        result.findings.extend(_scan_content(content, path, compiled))
    except OSError as e:
        raise RuntimeError(f"Cannot read file: {e}") from e

    result.findings.sort(key=lambda f: (f.sort_key, f.line_number))
    return result


def _walk(root: Path):
    """Yield all files under root, skipping ignored dirs."""
    for entry in root.iterdir():
        if entry.is_dir():
            if not _should_skip_dir(entry.name):
                yield from _walk(entry)
        elif entry.is_file():
            yield entry
