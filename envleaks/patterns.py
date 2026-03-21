"""
Secret detection patterns.
Each pattern has: id, name, regex, severity, description
"""

from dataclasses import dataclass
import re


@dataclass
class Pattern:
    id: str
    name: str
    regex: str
    severity: str  # critical / high / medium / low
    description: str

    def compile(self) -> re.Pattern:
        return re.compile(self.regex, re.IGNORECASE)


PATTERNS: list[Pattern] = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    Pattern("AWS001", "AWS Access Key ID",
            r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
            "critical", "AWS Access Key ID"),
    Pattern("AWS002", "AWS Secret Access Key",
            r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            "critical", "AWS Secret Access Key"),
    Pattern("AWS003", "AWS Session Token",
            r"(?i)aws[_\-\s]?session[_\-\s]?token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
            "high", "AWS Session Token"),

    # ── GitHub ────────────────────────────────────────────────────────────────
    Pattern("GH001", "GitHub Personal Access Token (classic)",
            r"ghp_[A-Za-z0-9]{36}",
            "critical", "GitHub classic PAT"),
    Pattern("GH002", "GitHub OAuth Token",
            r"gho_[A-Za-z0-9]{36}",
            "critical", "GitHub OAuth token"),
    Pattern("GH003", "GitHub App Token",
            r"(ghu|ghs)_[A-Za-z0-9]{36}",
            "critical", "GitHub App token"),
    Pattern("GH004", "GitHub Refresh Token",
            r"ghr_[A-Za-z0-9]{76}",
            "high", "GitHub refresh token"),
    Pattern("GH005", "GitHub Fine-Grained PAT",
            r"github_pat_[A-Za-z0-9_]{82}",
            "critical", "GitHub fine-grained PAT"),

    # ── Google ────────────────────────────────────────────────────────────────
    Pattern("GG001", "Google API Key",
            r"AIza[0-9A-Za-z\-_]{35}",
            "high", "Google API key"),
    Pattern("GG002", "Google OAuth Client Secret",
            r"(?i)google[_\-\s]?(?:oauth[_\-\s]?)?client[_\-\s]?secret\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{24})['\"]?",
            "high", "Google OAuth client secret"),
    Pattern("GG003", "Google Service Account Key",
            r'"type"\s*:\s*"service_account"',
            "critical", "Google service account JSON key"),

    # ── OpenAI ────────────────────────────────────────────────────────────────
    Pattern("OAI001", "OpenAI API Key",
            r"sk-[A-Za-z0-9]{48}",
            "critical", "OpenAI API key"),
    Pattern("OAI002", "OpenAI Organization ID",
            r"org-[A-Za-z0-9]{24}",
            "medium", "OpenAI organization ID"),

    # ── Anthropic ─────────────────────────────────────────────────────────────
    Pattern("ANT001", "Anthropic API Key",
            r"sk-ant-[A-Za-z0-9\-_]{93}",
            "critical", "Anthropic API key"),

    # ── Stripe ────────────────────────────────────────────────────────────────
    Pattern("STR001", "Stripe Live Secret Key",
            r"sk_live_[A-Za-z0-9]{24,}",
            "critical", "Stripe live secret key"),
    Pattern("STR002", "Stripe Test Secret Key",
            r"sk_test_[A-Za-z0-9]{24,}",
            "medium", "Stripe test secret key"),
    Pattern("STR003", "Stripe Webhook Secret",
            r"whsec_[A-Za-z0-9]{32,}",
            "high", "Stripe webhook secret"),
    Pattern("STR004", "Stripe Publishable Key",
            r"pk_(live|test)_[A-Za-z0-9]{24,}",
            "low", "Stripe publishable key"),

    # ── Slack ─────────────────────────────────────────────────────────────────
    Pattern("SLK001", "Slack Bot Token",
            r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{23,25}",
            "critical", "Slack bot token"),
    Pattern("SLK002", "Slack User Token",
            r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}",
            "critical", "Slack user token"),
    Pattern("SLK003", "Slack App Token",
            r"xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+",
            "high", "Slack app-level token"),
    Pattern("SLK004", "Slack Webhook URL",
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            "high", "Slack incoming webhook URL"),

    # ── Twilio ────────────────────────────────────────────────────────────────
    Pattern("TWL001", "Twilio Account SID",
            r"AC[a-z0-9]{32}",
            "high", "Twilio Account SID"),
    Pattern("TWL002", "Twilio Auth Token",
            r"(?i)twilio[_\-\s]?auth[_\-\s]?token\s*[=:]\s*['\"]?([a-z0-9]{32})['\"]?",
            "critical", "Twilio auth token"),

    # ── SendGrid ──────────────────────────────────────────────────────────────
    Pattern("SG001", "SendGrid API Key",
            r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
            "critical", "SendGrid API key"),

    # ── Mailgun ───────────────────────────────────────────────────────────────
    Pattern("MG001", "Mailgun API Key",
            r"key-[A-Za-z0-9]{32}",
            "high", "Mailgun API key"),

    # ── Cloudflare ────────────────────────────────────────────────────────────
    Pattern("CF001", "Cloudflare API Token",
            r"(?i)cloudflare[_\-\s]?(?:api[_\-\s]?)?token\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{40})['\"]?",
            "critical", "Cloudflare API token"),
    Pattern("CF002", "Cloudflare Global API Key",
            r"(?i)cloudflare[_\-\s]?(?:global[_\-\s]?)?(?:api[_\-\s]?)?key\s*[=:]\s*['\"]?([a-f0-9]{37})['\"]?",
            "critical", "Cloudflare global API key"),

    # ── DigitalOcean ──────────────────────────────────────────────────────────
    Pattern("DO001", "DigitalOcean Personal Access Token",
            r"dop_v1_[A-Za-z0-9]{64}",
            "critical", "DigitalOcean PAT"),
    Pattern("DO002", "DigitalOcean Spaces Key",
            r"(?i)digitalocean[_\-\s]?spaces[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9]{20})['\"]?",
            "high", "DigitalOcean Spaces access key"),

    # ── Azure ─────────────────────────────────────────────────────────────────
    Pattern("AZ001", "Azure Storage Account Key",
            r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88})",
            "critical", "Azure storage connection string"),
    Pattern("AZ002", "Azure AD Client Secret",
            r"(?i)azure[_\-\s]?(?:ad[_\-\s]?)?client[_\-\s]?secret\s*[=:]\s*['\"]?([A-Za-z0-9~._\-]{34,})['\"]?",
            "critical", "Azure AD client secret"),

    # ── Database ──────────────────────────────────────────────────────────────
    Pattern("DB001", "Generic Database URL",
            r"(?i)(postgres|postgresql|mysql|mongodb|redis|mssql|sqlite)://[^:]+:[^@]+@[^\s'\"]+",
            "critical", "Database connection URL with credentials"),
    Pattern("DB002", "MongoDB Atlas URI",
            r"mongodb\+srv://[^:]+:[^@]+@[^\s'\"]+",
            "critical", "MongoDB Atlas connection string"),

    # ── Private Keys ──────────────────────────────────────────────────────────
    Pattern("PK001", "RSA Private Key",
            r"-----BEGIN RSA PRIVATE KEY-----",
            "critical", "RSA private key"),
    Pattern("PK002", "EC Private Key",
            r"-----BEGIN EC PRIVATE KEY-----",
            "critical", "EC private key"),
    Pattern("PK003", "OpenSSH Private Key",
            r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "critical", "OpenSSH private key"),
    Pattern("PK004", "PGP Private Key",
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "critical", "PGP private key"),
    Pattern("PK005", "Generic Private Key",
            r"-----BEGIN PRIVATE KEY-----",
            "critical", "Private key (PKCS#8)"),

    # ── JWT ───────────────────────────────────────────────────────────────────
    Pattern("JWT001", "JSON Web Token",
            r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            "high", "JSON Web Token"),

    # ── NPM / Package registries ──────────────────────────────────────────────
    Pattern("NPM001", "NPM Auth Token",
            r"//registry\.npmjs\.org/:_authToken=['\"]?([A-Za-z0-9\-_]{36})['\"]?",
            "critical", "npm registry auth token"),
    Pattern("NPM002", "NPM Access Token",
            r"npm_[A-Za-z0-9]{36}",
            "critical", "npm access token"),

    # ── Docker ────────────────────────────────────────────────────────────────
    Pattern("DCK001", "Docker Hub Password",
            r"(?i)docker[_\-\s]?(?:hub[_\-\s]?)?password\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
            "high", "Docker Hub password"),

    # ── Heroku ────────────────────────────────────────────────────────────────
    Pattern("HRK001", "Heroku API Key",
            r"(?i)heroku[_\-\s]?(?:api[_\-\s]?)?key\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
            "critical", "Heroku API key"),

    # ── Generic high-entropy secrets ──────────────────────────────────────────
    Pattern("GEN001", "Generic Secret Assignment",
            r"(?i)(?:secret|password|passwd|pwd|api[_\-]?key|auth[_\-]?token|access[_\-]?token|private[_\-]?key)\s*[=:]\s*['\"]([A-Za-z0-9+/=_\-@!#]{16,})['\"]",
            "medium", "Generic secret/password assignment"),
    Pattern("GEN002", "Generic Bearer Token in Code",
            r"(?i)Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)",
            "high", "Hardcoded Bearer token"),
    Pattern("GEN003", "Basic Auth in URL",
            r"https?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-!@#$%^&*]{6,}@",
            "high", "Credentials embedded in URL"),

    # ── .env file indicators ──────────────────────────────────────────────────
    Pattern("ENV001", "Dotenv File Content",
            r"^[A-Z][A-Z0-9_]{2,}=.{4,}$",
            "low", "Possible .env variable with value"),

    # ── CI/CD ─────────────────────────────────────────────────────────────────
    Pattern("CI001", "CircleCI Token",
            r"(?i)circle[_\-\s]?(?:ci[_\-\s]?)?token\s*[=:]\s*['\"]?([A-Za-z0-9]{40})['\"]?",
            "critical", "CircleCI API token"),
    Pattern("CI002", "Travis CI Token",
            r"(?i)travis[_\-\s]?(?:ci[_\-\s]?)?token\s*[=:]\s*['\"]?([A-Za-z0-9]{22})['\"]?",
            "critical", "Travis CI token"),

    # ── Telegram ─────────────────────────────────────────────────────────────
    Pattern("TG001", "Telegram Bot Token",
            r"\d{8,10}:[A-Za-z0-9_\-]{35}",
            "critical", "Telegram bot token"),

    # ── Discord ───────────────────────────────────────────────────────────────
    Pattern("DS001", "Discord Bot Token",
            r"(?:mfa\.|[A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_\-]{27})",
            "critical", "Discord bot token"),
    Pattern("DS002", "Discord Webhook URL",
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+",
            "high", "Discord webhook URL"),

    # ── Shodan ────────────────────────────────────────────────────────────────
    Pattern("SHD001", "Shodan API Key",
            r"(?i)shodan[_\-\s]?(?:api[_\-\s]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9]{32})['\"]?",
            "high", "Shodan API key"),

    # ── Firebase ──────────────────────────────────────────────────────────────
    Pattern("FB001", "Firebase URL",
            r"https://[a-z0-9\-]+\.firebaseio\.com",
            "medium", "Firebase database URL (check if public)"),
    Pattern("FB002", "Firebase Server Key",
            r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
            "critical", "Firebase Cloud Messaging server key"),

    # ── Sensitive filenames ───────────────────────────────────────────────────
    Pattern("FILE001", "Dotenv File",
            r"(?:^|/)\.env(?:\.|$)",
            "high", ".env file committed"),
    Pattern("FILE002", "Private Key File",
            r"(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pub)?$",
            "critical", "SSH private/public key file"),
    Pattern("FILE003", "Keystore File",
            r"(?:^|/).*\.(?:jks|keystore|p12|pfx)$",
            "high", "Java keystore or certificate file"),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}
