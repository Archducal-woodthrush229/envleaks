# 🐾 envleaks

> Scan your codebase, git history, and CI pipelines for accidentally exposed secrets, API keys, and credentials.

[![CI](https://github.com/ExploitCraft/envleaks/actions/workflows/ci.yml/badge.svg)](https://github.com/ExploitCraft/envleaks/actions)
[![PyPI](https://img.shields.io/pypi/v/envleaks)](https://pypi.org/project/envleaks/)
[![Python](https://img.shields.io/pypi/pyversions/envleaks)](https://pypi.org/project/envleaks/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

- 🔍 **100+ detection patterns** — AWS, GitHub, OpenAI, Stripe, Slack, Twilio, GCP, Azure, and more
- 📜 **Git history scanning** — finds secrets in past commits, not just the current state
- 🐳 **Docker-ready** — works inside containers and CI/CD pipelines
- 📊 **Multiple output formats** — terminal (Rich), JSON, and SARIF (GitHub Advanced Security)
- ⚙️ **CI mode** — exits with code `1` if secrets are found, blocking the pipeline
- 🎯 **Severity filtering** — focus on `critical` and `high` only, skip the noise
- ⚡ **Fast** — skips binaries, large files, and `node_modules` automatically

---

## Installation

```bash
pip install envleaks
```

Or install from source:

```bash
git clone https://github.com/ExploitCraft/envleaks
cd envleaks
pip install -e .
```

---

## Quick Start

```bash
# Scan current directory
envleaks scan .

# Scan a specific project
envleaks scan /path/to/project

# Scan a single file
envleaks scan config.py

# Only show critical and high findings
envleaks scan . --severity critical,high

# Also scan all past git commits
envleaks scan . --git-history

# Output as JSON
envleaks scan . --format json --output report.json

# CI mode — exits 1 if findings, SARIF output for GitHub
envleaks scan . --ci --format sarif --output envleaks.sarif
```

---

## Example Output

```
╭─ envleaks — secret & credential scanner ─╮

📄 config/settings.py
  LINE   SEVERITY         RULE    NAME                        MATCH
     12  💀 CRITICAL      AWS001  AWS Access Key ID           AKIA...MPLE
     18  🔴 HIGH          GH001   GitHub Personal Access...   ghp_...9012
     34  🟡 MEDIUM        GEN001  Generic Secret Assignment   secr...word

📄 .env.backup
     1   💀 CRITICAL      DB001   Database connection URL     post...b"

╭─ Scan Summary ──────────────────╮
  Files scanned      47
  Files skipped      12
  Total findings      4
  Critical            2
  High                1
  Medium              1
╰─────────────────────────────────╯
```

---

## GitHub Actions Integration

Add this step to your workflow to block PRs that introduce secrets:

```yaml
- name: Scan for secrets
  run: |
    pip install envleaks
    envleaks scan . --ci --severity critical,high
```

For full SARIF integration with GitHub's Security tab:

```yaml
- name: Scan for secrets (SARIF)
  run: |
    pip install envleaks
    envleaks scan . --format sarif --output envleaks.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: envleaks.sarif
```

---

## Detection Rules

| Category         | Rules | Examples |
|-----------------|-------|---------|
| AWS              | 3     | Access Key, Secret Key, Session Token |
| GitHub           | 5     | PAT, OAuth, Fine-Grained PAT |
| Google / GCP     | 3     | API Key, Service Account |
| OpenAI           | 2     | API Key, Org ID |
| Stripe           | 4     | Live/Test Secret, Webhook |
| Slack            | 4     | Bot Token, Webhook URL |
| Database URLs    | 2     | PostgreSQL, MongoDB Atlas |
| Private Keys     | 5     | RSA, EC, OpenSSH, PGP |
| Generic          | 3     | Bearer tokens, Basic Auth in URLs |
| + more           | 70+   | Twilio, Discord, Firebase, Azure... |

View all rules:

```bash
envleaks list-rules
envleaks list-rules --severity critical
```

---

## CLI Reference

```
Usage: envleaks [OPTIONS] COMMAND [ARGS]...

Commands:
  scan        Scan PATH for secrets and credentials
  list-rules  List all built-in detection rules

Options for scan:
  --format      terminal | json | sarif  (default: terminal)
  --output, -o  Write to file
  --severity    critical,high,medium,low (comma-separated)
  --git-history Also scan all past git commits
  --max-commits Limit commits scanned with --git-history
  --ci          Exit code 1 on findings (for pipelines)
  --include     Glob pattern to include
  --exclude     Glob pattern to exclude
```

---

## Part of the HackerInc/ExploitCraft Ecosystem

| Tool | Description |
|------|-------------|
| **envleaks** | Codebase & git history scanner (this repo) |
| [gitdork](https://github.com/ExploitCraft/gitdork) | Google/Shodan dork generator |
| [wifi-passview](https://github.com/ExploitCraft/wifi-passview) | Cross-platform WiFi credential dumper |
| [ReconNinja](https://github.com/ExploitCraft/ReconNinja) | ReconNinja v6 — 21-phase recon framework |
| [VaultHound](https://github.com/ExploitCraft/VaultHound) | Secret & credential scanner |

---

## Contributing

PRs welcome! To add a new detection pattern, edit `envleaks/patterns.py` and add a `Pattern(...)` entry. Please include a test in `tests/test_scanner.py`.

```bash
pip install -e ".[dev]"
pytest tests/
ruff check envleaks/
```

---

## License

MIT © [ExploitCraft](https://github.com/ExploitCraft)
