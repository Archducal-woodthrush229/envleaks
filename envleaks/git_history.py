"""
Git history scanner — walks every commit and scans blobs for secrets.
"""

from __future__ import annotations

from pathlib import Path

from .patterns import PATTERNS, SEVERITY_ORDER
from .scanner import ScanResult, _scan_content


def scan_git_history(
    repo_path: Path,
    max_commits: int | None = None,
    severity_filter: list[str] | None = None,
    progress_cb=None,
) -> ScanResult:
    """Scan all commits in a git repository for secrets."""
    try:
        import git
    except ImportError:
        raise RuntimeError(
            "GitPython is required for git history scanning.\n"
            "Install it with: pip install gitpython"
        )

    result = ScanResult()
    active_patterns = [
        p for p in PATTERNS
        if severity_filter is None or p.severity in severity_filter
    ]
    compiled = [(p, p.compile()) for p in active_patterns]

    try:
        repo = git.Repo(repo_path, search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        raise RuntimeError(f"'{repo_path}' is not inside a git repository.")

    commits = list(repo.iter_commits())
    if max_commits:
        commits = commits[:max_commits]

    seen_blobs: set[str] = set()
    total = len(commits)

    for i, commit in enumerate(commits):
        if progress_cb:
            progress_cb(i + 1, total, str(commit.hexsha[:8]))

        for blob in commit.tree.traverse():
            if blob.type != "blob":
                continue
            if blob.hexsha in seen_blobs:
                continue
            seen_blobs.add(blob.hexsha)

            # Skip binaries and large blobs
            if blob.size > 1 * 1024 * 1024:
                result.skipped_files += 1
                continue

            try:
                content = blob.data_stream.read().decode("utf-8", errors="replace")
            except Exception:
                result.skipped_files += 1
                continue

            result.scanned_files += 1
            file_path = Path(f"[{commit.hexsha[:8]}] {blob.path}")
            findings = _scan_content(content, file_path, compiled)

            for f in findings:
                f.line_content = f"commit:{commit.hexsha[:8]} | {f.line_content}"

            result.findings.extend(findings)

    result.findings.sort(key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 99), str(f.file), f.line_number
    ))
    return result
