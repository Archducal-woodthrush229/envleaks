# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2024-01-01

### Added
- Initial release
- 100+ secret detection patterns across AWS, GitHub, Google, OpenAI, Stripe, Slack, and more
- Directory and single-file scanning
- Git history scanning via `--git-history`
- Terminal (Rich), JSON, and SARIF output formats
- CI mode with `--ci` flag (exits 1 on findings)
- Severity filtering with `--severity`
- `list-rules` command to browse all detection rules
