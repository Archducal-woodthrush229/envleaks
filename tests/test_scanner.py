"""Tests for the core scanner."""

import textwrap
from pathlib import Path
import pytest
import tempfile

from envleaks.scanner import scan_file, scan_directory
from envleaks.patterns import PATTERNS


def write_temp(content: str, suffix=".py") -> Path:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="w", encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


class TestPatternMatching:
    def test_aws_access_key(self):
        path = write_temp('key = "AKIAIOSFODNN7EXAMPLE"')
        result = scan_file(path)
        assert any(f.pattern.id == "AWS001" for f in result.findings)

    def test_github_pat(self):
        path = write_temp('token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012"')
        result = scan_file(path)
        assert any(f.pattern.id == "GH001" for f in result.findings)

    def test_openai_key(self):
        path = write_temp('OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW"')
        result = scan_file(path)
        assert any(f.pattern.id == "OAI001" for f in result.findings)

    def test_private_key(self):
        path = write_temp("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")
        result = scan_file(path)
        assert any(f.pattern.id == "PK001" for f in result.findings)

    def test_database_url(self):
        path = write_temp('DB_URL = "postgresql://admin:s3cr3t@localhost:5432/mydb"')
        result = scan_file(path)
        assert any(f.pattern.id == "DB001" for f in result.findings)

    def test_slack_webhook(self):
        # URL is intentionally fake/test-only — split to avoid scanner triggers
        fake = "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        path = write_temp(f'WEBHOOK = "{fake}"')
        result = scan_file(path)
        assert any(f.pattern.id == "SLK004" for f in result.findings)

    def test_no_findings_clean_file(self):
        path = write_temp(textwrap.dedent("""
            def hello():
                name = "world"
                print(f"hello {name}")
        """))
        result = scan_file(path)
        assert not result.has_findings

    def test_severity_filter(self):
        path = write_temp('key = "AKIAIOSFODNN7EXAMPLE"')
        result = scan_file(path, severity_filter=["low"])
        # AWS001 is critical, should be excluded
        assert not any(f.pattern.id == "AWS001" for f in result.findings)


class TestDirectoryScanner:
    def test_scan_directory(self, tmp_path):
        (tmp_path / "config.py").write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / "clean.py").write_text('x = 1\n')
        result = scan_directory(tmp_path)
        assert result.scanned_files >= 1
        assert result.has_findings

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "secret.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE"')
        result = scan_directory(tmp_path)
        assert not result.has_findings

    def test_finding_has_correct_line_number(self, tmp_path):
        content = "x = 1\ny = 2\nAPI_KEY = 'AKIAIOSFODNN7EXAMPLE'\nz = 3\n"
        (tmp_path / "test.py").write_text(content)
        result = scan_directory(tmp_path)
        aws_findings = [f for f in result.findings if f.pattern.id == "AWS001"]
        assert aws_findings
        assert aws_findings[0].line_number == 3


class TestPatternCoverage:
    def test_all_patterns_compile(self):
        for p in PATTERNS:
            import re
            compiled = re.compile(p.regex, re.IGNORECASE)
            assert compiled is not None

    def test_pattern_ids_unique(self):
        ids = [p.id for p in PATTERNS]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"
