"""
Comprehensive tests for envleaks.

All fake secrets are intentionally malformed / split to avoid
GitHub push protection triggering on the test file itself.
"""

from __future__ import annotations

import re
import tempfile
import textwrap
from pathlib import Path

import pytest

from envleaks.patterns import PATTERNS, SEVERITY_COLORS, SEVERITY_ORDER
from envleaks.scanner import (
    _should_skip_dir,
    _should_skip_file,
    scan_directory,
    scan_file,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def tmp_file(content: str, suffix: str = ".py") -> Path:
    f = tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, mode="w", encoding="utf-8"
    )
    f.write(content)
    f.close()
    return Path(f.name)


def has_rule(findings, rule_id: str) -> bool:
    return any(f.pattern.id == rule_id for f in findings)


# ── AWS ───────────────────────────────────────────────────────────────────────

class TestAWSPatterns:
    def test_aws001_access_key(self):
        path = tmp_file('key = "AKIAIOSFODNN7EXAMPLE"')
        assert has_rule(scan_file(path).findings, "AWS001")

    def test_aws001_abia_prefix(self):
        path = tmp_file('key = "ABIAIOSFODNN7EXAMPLE"')
        assert has_rule(scan_file(path).findings, "AWS001")

    def test_aws001_not_matched_short(self):
        path = tmp_file('key = "AKIA123"')
        assert not has_rule(scan_file(path).findings, "AWS001")

    def test_aws002_secret_key(self):
        path = tmp_file(
            'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        )
        assert has_rule(scan_file(path).findings, "AWS002")

    def test_aws003_session_token(self):
        token = "A" * 110
        path = tmp_file(f'aws_session_token = "{token}"')
        assert has_rule(scan_file(path).findings, "AWS003")


# ── GitHub ────────────────────────────────────────────────────────────────────

class TestGitHubPatterns:
    def test_gh001_classic_pat(self):
        tok = "ghp_" + "a" * 36
        path = tmp_file(f'TOKEN = "{tok}"')
        assert has_rule(scan_file(path).findings, "GH001")

    def test_gh002_oauth_token(self):
        tok = "gho_" + "b" * 36
        path = tmp_file(f'OAUTH = "{tok}"')
        assert has_rule(scan_file(path).findings, "GH002")

    def test_gh003_app_token_ghu(self):
        tok = "ghu_" + "c" * 36
        path = tmp_file(f'APP_TOKEN = "{tok}"')
        assert has_rule(scan_file(path).findings, "GH003")

    def test_gh003_app_token_ghs(self):
        tok = "ghs_" + "d" * 36
        path = tmp_file(f'APP_TOKEN = "{tok}"')
        assert has_rule(scan_file(path).findings, "GH003")

    def test_gh005_fine_grained_pat(self):
        tok = "github_pat_" + "A" * 82
        path = tmp_file(f'TOKEN = "{tok}"')
        assert has_rule(scan_file(path).findings, "GH005")


# ── OpenAI / Anthropic ────────────────────────────────────────────────────────

class TestAIKeyPatterns:
    def test_oai001_openai_key(self):
        key = "sk-" + "x" * 48
        path = tmp_file(f'OPENAI_KEY = "{key}"')
        assert has_rule(scan_file(path).findings, "OAI001")

    def test_oai002_org_id(self):
        path = tmp_file('ORG = "org-' + "A" * 24 + '"')
        assert has_rule(scan_file(path).findings, "OAI002")

    def test_ant001_anthropic_key(self):
        key = "sk-ant-" + "A" * 93
        path = tmp_file(f'ANTHROPIC_KEY = "{key}"')
        assert has_rule(scan_file(path).findings, "ANT001")


# ── Stripe ────────────────────────────────────────────────────────────────────

class TestStripePatterns:
    def test_str001_live_secret(self):
        path = tmp_file('SK = "sk_live_' + "a" * 24 + '"')
        assert has_rule(scan_file(path).findings, "STR001")

    def test_str002_test_secret(self):
        path = tmp_file('SK = "sk_test_' + "a" * 24 + '"')
        assert has_rule(scan_file(path).findings, "STR002")

    def test_str003_webhook_secret(self):
        path = tmp_file('WH = "whsec_' + "a" * 32 + '"')
        assert has_rule(scan_file(path).findings, "STR003")

    def test_str004_publishable_key(self):
        path = tmp_file('PK = "pk_live_' + "a" * 24 + '"')
        assert has_rule(scan_file(path).findings, "STR004")


# ── Slack ─────────────────────────────────────────────────────────────────────

class TestSlackPatterns:
    def test_slk001_bot_token(self):
        tok = "xoxb-1234567890-1234567890-" + "a" * 24
        path = tmp_file(f'BOT = "{tok}"')
        assert has_rule(scan_file(path).findings, "SLK001")

    def test_slk004_webhook_url(self):
        url = (
            "https://hooks.slack.com/services/"
            + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        )
        path = tmp_file(f'WH = "{url}"')
        assert has_rule(scan_file(path).findings, "SLK004")


# ── Private Keys ──────────────────────────────────────────────────────────────

class TestPrivateKeyPatterns:
    def test_pk001_rsa(self):
        path = tmp_file(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
        )
        assert has_rule(scan_file(path).findings, "PK001")

    def test_pk002_ec(self):
        path = tmp_file(
            "-----BEGIN EC PRIVATE KEY-----\nMHQ\n-----END EC PRIVATE KEY-----"
        )
        assert has_rule(scan_file(path).findings, "PK002")

    def test_pk003_openssh(self):
        path = tmp_file(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----"
        )
        assert has_rule(scan_file(path).findings, "PK003")

    def test_pk004_pgp(self):
        path = tmp_file(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQI\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        assert has_rule(scan_file(path).findings, "PK004")

    def test_pk005_pkcs8(self):
        path = tmp_file(
            "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"
        )
        assert has_rule(scan_file(path).findings, "PK005")


# ── Database URLs ─────────────────────────────────────────────────────────────

class TestDatabasePatterns:
    def test_db001_postgres(self):
        path = tmp_file('DB = "postgresql://admin:s3cr3t@localhost:5432/mydb"')
        assert has_rule(scan_file(path).findings, "DB001")

    def test_db001_mysql(self):
        path = tmp_file('DB = "mysql://root:password@127.0.0.1/app"')
        assert has_rule(scan_file(path).findings, "DB001")

    def test_db001_mongodb(self):
        path = tmp_file('DB = "mongodb://user:pass@mongo:27017/db"')
        assert has_rule(scan_file(path).findings, "DB001")

    def test_db001_redis(self):
        path = tmp_file('DB = "redis://user:s3cr3t@localhost:6379/0"')
        assert has_rule(scan_file(path).findings, "DB001")

    def test_db002_mongodb_atlas(self):
        path = tmp_file(
            'DB = "mongodb+srv://user:pass@cluster0.example.mongodb.net/mydb"'
        )
        assert has_rule(scan_file(path).findings, "DB002")


# ── JWT ───────────────────────────────────────────────────────────────────────

class TestJWTPattern:
    def test_jwt001_standard_token(self):
        header  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
        sig     = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        path = tmp_file(f'TOKEN = "{header}.{payload}.{sig}"')
        assert has_rule(scan_file(path).findings, "JWT001")


# ── Generic ───────────────────────────────────────────────────────────────────

class TestGenericPatterns:
    def test_gen001_secret_assignment(self):
        path = tmp_file('secret = "MySuperSecretValue123456"')
        assert has_rule(scan_file(path).findings, "GEN001")

    def test_gen001_password_assignment(self):
        path = tmp_file('password = "hunter2ButLongerNow!!"')
        assert has_rule(scan_file(path).findings, "GEN001")

    def test_gen001_short_value_not_matched(self):
        path = tmp_file('password = "short"')
        assert not has_rule(scan_file(path).findings, "GEN001")

    def test_gen003_basic_auth_in_url(self):
        path = tmp_file('url = "https://admin:p4ssw0rd@example.com/api"')
        assert has_rule(scan_file(path).findings, "GEN003")


# ── NPM ───────────────────────────────────────────────────────────────────────

class TestNPMPatterns:
    def test_npm002_access_token(self):
        tok = "npm_" + "A" * 36
        path = tmp_file(f'TOKEN = "{tok}"', suffix=".js")
        assert has_rule(scan_file(path).findings, "NPM002")


# ── Discord ───────────────────────────────────────────────────────────────────

class TestDiscordPatterns:
    def test_ds002_webhook_url(self):
        url = (
            "https://discord.com/api/webhooks/123456789012345678/" + "a" * 68
        )
        path = tmp_file(f'WEBHOOK = "{url}"')
        assert has_rule(scan_file(path).findings, "DS002")


# ── Firebase ──────────────────────────────────────────────────────────────────

class TestFirebasePatterns:
    def test_fb001_database_url(self):
        path = tmp_file('DB = "https://my-app-default-rtdb.firebaseio.com"')
        assert has_rule(scan_file(path).findings, "FB001")


# ── No false positives ────────────────────────────────────────────────────────

class TestNoFalsePositives:
    def test_clean_python_file(self):
        path = tmp_file(textwrap.dedent("""
            def greet(name: str) -> str:
                return f"Hello, {name}!"

            class Config:
                debug = True
                host = "localhost"
                port = 8080
        """))
        assert not scan_file(path).has_findings

    def test_clean_env_example(self):
        path = tmp_file(
            "DATABASE_URL=your-database-url-here\n"
            "API_KEY=your-api-key-here\n",
            suffix=".env",
        )
        assert not scan_file(path, severity_filter=["critical"]).has_findings

    def test_comments_with_keyword(self):
        path = tmp_file(
            "# Set your API key here\n"
            "# password: see docs\n"
        )
        assert not scan_file(path, severity_filter=["critical"]).has_findings


# ── Severity filter ───────────────────────────────────────────────────────────

class TestSeverityFilter:
    def test_critical_filter_excludes_medium(self):
        path = tmp_file('secret = "MySuperSecretValue123456"')  # GEN001 = medium
        assert not has_rule(
            scan_file(path, severity_filter=["critical"]).findings, "GEN001"
        )

    def test_critical_filter_includes_aws(self):
        path = tmp_file('key = "AKIAIOSFODNN7EXAMPLE"')
        assert has_rule(
            scan_file(path, severity_filter=["critical"]).findings, "AWS001"
        )

    def test_multiple_severities(self):
        content = (
            'key = "AKIAIOSFODNN7EXAMPLE"\n'
            'secret = "MySuperSecretValue123456"\n'
        )
        path = tmp_file(content)
        result = scan_file(path, severity_filter=["critical", "medium"])
        assert has_rule(result.findings, "AWS001")
        assert has_rule(result.findings, "GEN001")


# ── ScanResult counters ───────────────────────────────────────────────────────

class TestScanResult:
    def test_critical_count(self, tmp_path):
        (tmp_path / "f.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        result = scan_directory(tmp_path)
        assert result.critical_count >= 1

    def test_has_findings_false_on_clean(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        assert not scan_directory(tmp_path).has_findings

    def test_scanned_files_count(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        assert scan_directory(tmp_path).scanned_files == 2


# ── Directory scanner ─────────────────────────────────────────────────────────

class TestDirectoryScanner:
    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "secret.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE"')
        assert not scan_directory(tmp_path).has_findings

    def test_skips_pycache(self, tmp_path):
        pc = tmp_path / "__pycache__"
        pc.mkdir()
        (pc / "secret.pyc").write_text('key = "AKIAIOSFODNN7EXAMPLE"')
        assert not scan_directory(tmp_path).has_findings

    def test_skips_venv(self, tmp_path):
        venv = tmp_path / ".venv"
        venv.mkdir()
        (venv / "secret.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"')
        assert not scan_directory(tmp_path).has_findings

    def test_skips_binary_extensions(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG AKIAIOSFODNN7EXAMPLE")
        result = scan_directory(tmp_path)
        assert result.skipped_files == 1
        assert not result.has_findings

    def test_correct_line_number(self, tmp_path):
        (tmp_path / "f.py").write_text(
            "x = 1\ny = 2\nkey = 'AKIAIOSFODNN7EXAMPLE'\nz = 3\n"
        )
        findings = [
            f for f in scan_directory(tmp_path).findings
            if f.pattern.id == "AWS001"
        ]
        assert findings[0].line_number == 3

    def test_multiple_secrets_in_one_file(self, tmp_path):
        tok = "ghp_" + "a" * 36
        (tmp_path / "config.py").write_text(
            f'TOKEN = "{tok}"\n'
            'key = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        assert scan_directory(tmp_path).critical_count >= 2

    def test_include_glob_filter(self, tmp_path):
        (tmp_path / "main.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / "main.js").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        result = scan_directory(tmp_path, include_patterns=["*.py"])
        assert result.scanned_files == 1

    def test_exclude_glob_filter(self, tmp_path):
        (tmp_path / "main.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / "test.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        result = scan_directory(tmp_path, exclude_patterns=["test.py"])
        assert result.scanned_files == 1

    def test_nested_directory(self, tmp_path):
        sub = tmp_path / "src" / "config"
        sub.mkdir(parents=True)
        (sub / "settings.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        assert scan_directory(tmp_path).has_findings

    def test_finding_match_is_redacted(self, tmp_path):
        (tmp_path / "f.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        aws = [
            f for f in scan_directory(tmp_path).findings
            if f.pattern.id == "AWS001"
        ]
        assert aws
        assert "..." in aws[0].match

    def test_findings_sorted_by_severity(self, tmp_path):
        tok = "ghp_" + "a" * 36
        (tmp_path / "f.py").write_text(
            'secret = "MySuperSecretValue123456"\n'
            f'TOKEN = "{tok}"\n'
            'key = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        result = scan_directory(tmp_path)
        order = [SEVERITY_ORDER[f.severity] for f in result.findings]
        assert order == sorted(order)


# ── Skip helpers ──────────────────────────────────────────────────────────────

class TestSkipHelpers:
    def test_skip_dir_node_modules(self):
        assert _should_skip_dir("node_modules") is True

    def test_skip_dir_pycache(self):
        assert _should_skip_dir("__pycache__") is True

    def test_skip_dir_hidden(self):
        assert _should_skip_dir(".git") is True

    def test_skip_dir_normal(self):
        assert _should_skip_dir("src") is False

    def test_skip_file_png(self, tmp_path):
        p = tmp_path / "img.png"
        p.write_bytes(b"\x89PNG")
        assert _should_skip_file(p) is True

    def test_skip_file_large(self, tmp_path):
        p = tmp_path / "big.py"
        p.write_bytes(b"x" * (2 * 1024 * 1024))
        assert _should_skip_file(p) is True

    def test_no_skip_normal_py(self, tmp_path):
        p = tmp_path / "main.py"
        p.write_text("x = 1\n")
        assert _should_skip_file(p) is False


# ── Pattern metadata ──────────────────────────────────────────────────────────

class TestPatternMetadata:
    def test_all_patterns_compile(self):
        for p in PATTERNS:
            compiled = re.compile(p.regex, re.IGNORECASE)
            assert compiled is not None, f"{p.id} regex failed to compile"

    def test_pattern_ids_unique(self):
        ids = [p.id for p in PATTERNS]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs detected"

    def test_all_patterns_have_valid_severity(self):
        valid = {"critical", "high", "medium", "low"}
        for p in PATTERNS:
            assert p.severity in valid, f"{p.id} has invalid severity"

    def test_all_patterns_have_description(self):
        for p in PATTERNS:
            assert p.description, f"{p.id} is missing a description"

    def test_severity_order_covers_all(self):
        for p in PATTERNS:
            assert p.severity in SEVERITY_ORDER

    def test_severity_colors_covers_all(self):
        for p in PATTERNS:
            assert p.severity in SEVERITY_COLORS

    def test_pattern_count_regression(self):
        assert len(PATTERNS) >= 50, f"Expected 50+ patterns, got {len(PATTERNS)}"


# ── JSON reporter ─────────────────────────────────────────────────────────────

class TestJSONReporter:
    def test_json_output_structure(self, tmp_path):
        from envleaks.reporters.json_report import to_dict

        (tmp_path / "f.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        data = to_dict(scan_directory(tmp_path), root=tmp_path)

        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["total_findings"] >= 1
        assert data["summary"]["critical"] >= 1

    def test_json_finding_fields(self, tmp_path):
        from envleaks.reporters.json_report import to_dict

        (tmp_path / "f.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        data = to_dict(scan_directory(tmp_path), root=tmp_path)
        f = data["findings"][0]

        for field in ("rule_id", "severity", "file", "line", "match"):
            assert field in f

    def test_json_write_to_file(self, tmp_path):
        import json
        from envleaks.reporters.json_report import write

        (tmp_path / "f.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        out = tmp_path / "report.json"
        write(scan_directory(tmp_path), out, root=tmp_path)

        assert out.exists()
        assert json.loads(out.read_text())["summary"]["total_findings"] >= 1


# ── SARIF reporter ────────────────────────────────────────────────────────────

class TestSARIFReporter:
    def test_sarif_structure(self, tmp_path):
        from envleaks.reporters.sarif import to_sarif

        (tmp_path / "f.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        data = to_sarif(scan_directory(tmp_path), root=tmp_path)

        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) >= 1

    def test_sarif_result_level(self, tmp_path):
        from envleaks.reporters.sarif import to_sarif

        (tmp_path / "f.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        data = to_sarif(scan_directory(tmp_path), root=tmp_path)
        level = data["runs"][0]["results"][0]["level"]
        assert level in {"error", "warning", "note"}
