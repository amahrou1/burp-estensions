# -*- coding: utf-8 -*-
# regex_engine.py - Pattern registry and scan logic
# Jython 2.7 compatible

import re
from secret_utils import validate_jwt

# ---------------------------------------------------------------------------
# Category constants
# ---------------------------------------------------------------------------

CAT_JWT = "JWT / Auth Tokens"
CAT_CLOUD = "Cloud Provider Secrets"
CAT_DATABASE = "Database Credentials"
CAT_PAYMENT = "Payment / Financial"
CAT_COMMUNICATION = "Communication Services"
CAT_AUTH = "Auth Provider Secrets"
CAT_CICD = "CI/CD & DevOps"
CAT_APIKEY = "API Keys & Generic Secrets"
CAT_PRIVATE_KEY = "Private Keys & Certificates"

# ---------------------------------------------------------------------------
# Password validator (for Pattern 44)
# ---------------------------------------------------------------------------

_PASSWORD_FALSE_POSITIVES = [
    "password", "changeme", "placeholder", "example",
    "xxxxxxxx", "********", "your_password", "undefined",
    "null", "none", "todo", "fixme", "replace_me",
    "insert_here", "your-password", "<password>",
]


def _validate_password(match):
    """Reject common false-positive password values."""
    try:
        val = match.lower().strip("\"'")
        for delim in ["=", ":"]:
            if delim in val:
                val = val.split(delim, 1)[1].strip().strip("\"'")
                break
        return val.lower() not in _PASSWORD_FALSE_POSITIVES and not val.startswith("$")
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Pattern registry
# Each entry: name, category, severity, confidence, compiled pattern,
#             optional validator callable, description, context_hint.
# ---------------------------------------------------------------------------

patterns = [

    # === JWT / Auth Tokens ================================================

    {
        "name": "JWT Token",
        "category": CAT_JWT,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{2,}"
        ),
        "validator": validate_jwt,
        "description": "JSON Web Token — decode header and payload to check for sensitive claims (sub, email, role, admin)",
        "context_hint": "Look for Authorization headers or token storage",
    },
    {
        "name": "Bearer Token",
        "category": CAT_JWT,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}"),
        "validator": None,
        "description": "Bearer authentication token in Authorization header",
        "context_hint": "Check Authorization header context",
    },

    # === Private Keys & Certificates ======================================

    {
        "name": "Private Key",
        "category": CAT_PRIVATE_KEY,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(
            r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        "validator": None,
        "description": "Private key block detected — check if the full key content follows",
        "context_hint": "Look for the complete key block ending with -----END PRIVATE KEY-----",
    },
    {
        "name": "Private Key (Encoded)",
        "category": CAT_PRIVATE_KEY,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(
            r"-----BEGIN\\\\n[A-Za-z0-9+/=\\\\n]{50,}-----END"
        ),
        "validator": None,
        "description": "Private key embedded as escaped string in JS/JSON — common in misconfigured apps",
        "context_hint": "Check if key is in a config object or environment variable",
    },

    # === Cloud Provider Secrets ===========================================

    {
        "name": "AWS Access Key ID",
        "category": CAT_CLOUD,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "validator": None,
        "description": "AWS IAM Access Key — look for corresponding Secret Access Key nearby",
        "context_hint": "Search for SecretAccessKey or aws_secret near this match",
    },
    {
        "name": "AWS Secret Access Key",
        "category": CAT_CLOUD,
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey|aws_secret)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
        ),
        "validator": None,
        "description": "AWS Secret Access Key — paired with AKIA key, provides full account access",
        "context_hint": "Should be paired with an AKIA access key ID",
    },
    {
        "name": "AWS Session Token",
        "category": CAT_CLOUD,
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:aws_session_token|AWS_SESSION_TOKEN|SessionToken)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?'
        ),
        "validator": None,
        "description": "AWS temporary session token — usually accompanied by access key and secret",
        "context_hint": "Look for access key and secret nearby",
    },
    {
        "name": "Google API Key",
        "category": CAT_CLOUD,
        "severity": "medium",
        "confidence": "high",
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "validator": None,
        "description": "Google API Key — check if restricted by referrer/IP or unrestricted",
        "context_hint": "Test key restrictions at Google Cloud Console",
    },
    {
        "name": "Google OAuth Secret",
        "category": CAT_CLOUD,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"GOCSPX-[A-Za-z0-9_-]{28}"),
        "validator": None,
        "description": "Google OAuth 2.0 Client Secret",
        "context_hint": "Look for client_id nearby",
    },
    {
        "name": "GCP Service Account",
        "category": CAT_CLOUD,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r'"type"\s*:\s*"service_account"'),
        "validator": None,
        "description": "Google Cloud service account JSON key file — likely contains private_key and client_email",
        "context_hint": "Check for private_key and client_email fields in the JSON",
    },
    {
        "name": "Firebase Config",
        "category": CAT_CLOUD,
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:apiKey|firebase)\s*[:=]\s*["\']AIza[0-9A-Za-z\-_]{35}["\']'
        ),
        "validator": None,
        "description": "Firebase API key in config object — check if Firebase Security Rules are properly configured",
        "context_hint": "Check Firebase Security Rules and API restrictions",
    },
    {
        "name": "Azure Client Secret",
        "category": CAT_CLOUD,
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:client_secret|AZURE_CLIENT_SECRET|azure_secret)\s*[:=]\s*["\']([A-Za-z0-9_~.\-]{34,})["\']'
        ),
        "validator": None,
        "description": "Azure AD application client secret",
        "context_hint": "Look for tenant_id and client_id nearby",
    },
    {
        "name": "Azure Storage Key",
        "category": CAT_CLOUD,
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:AccountKey|azure_storage_key)\s*[:=]\s*["\']?([A-Za-z0-9+/]{86}==)["\']?'
        ),
        "validator": None,
        "description": "Azure Storage Account access key — provides full access to storage account",
        "context_hint": "Look for AccountName nearby",
    },

    # === Database Credentials =============================================

    {
        "name": "MongoDB URI",
        "category": CAT_DATABASE,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(
            r"mongodb(\+srv)?://[A-Za-z0-9_%:@.\-]+(/[A-Za-z0-9_.\-]*)?(\?[A-Za-z0-9_=&.\-]*)?"
        ),
        "validator": None,
        "description": "MongoDB connection string — often contains username:password inline",
        "context_hint": "Check for credentials in the URI (user:pass@host)",
    },
    {
        "name": "PostgreSQL URI",
        "category": CAT_DATABASE,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(
            r"postgres(ql)?://[A-Za-z0-9_%:@.\-]+(/[A-Za-z0-9_.\-]*)?(\?[A-Za-z0-9_=&.\-]*)?"
        ),
        "validator": None,
        "description": "PostgreSQL connection string — likely contains credentials",
        "context_hint": "Check for credentials in the URI",
    },
    {
        "name": "MySQL URI",
        "category": CAT_DATABASE,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(
            r"mysql://[A-Za-z0-9_%:@.\-]+(/[A-Za-z0-9_.\-]*)?(\?[A-Za-z0-9_=&.\-]*)?"
        ),
        "validator": None,
        "description": "MySQL connection string",
        "context_hint": "Check for credentials in the URI",
    },
    {
        "name": "Redis URI",
        "category": CAT_DATABASE,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(
            r"redis(s)?://[A-Za-z0-9_%:@.\-]+(:[0-9]+)?(/[0-9]*)?"
        ),
        "validator": None,
        "description": "Redis connection string — may contain AUTH password",
        "context_hint": "Check for password in the URI",
    },

    # === Payment / Financial ==============================================

    {
        "name": "Stripe Secret Key",
        "category": CAT_PAYMENT,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
        "validator": None,
        "description": "Stripe live secret key — provides full API access to Stripe account",
        "context_hint": "Verify this is a live key (not test sk_test_)",
    },
    {
        "name": "Stripe Restricted Key",
        "category": CAT_PAYMENT,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"rk_live_[A-Za-z0-9]{20,}"),
        "validator": None,
        "description": "Stripe restricted API key",
        "context_hint": "Check key permissions in Stripe dashboard",
    },
    {
        "name": "PayPal Access Token",
        "category": CAT_PAYMENT,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"access_token\$production\$[A-Za-z0-9]{13,}"),
        "validator": None,
        "description": "PayPal production access token",
        "context_hint": "Production token — can process real payments",
    },
    {
        "name": "Square Access Token",
        "category": CAT_PAYMENT,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"sq0[a-z]{3}-[A-Za-z0-9_\-]{22,}"),
        "validator": None,
        "description": "Square API access token",
        "context_hint": "Check if sandbox or production token",
    },

    # === Communication Services ===========================================

    {
        "name": "Twilio API Key",
        "category": CAT_COMMUNICATION,
        "severity": "medium",
        "confidence": "high",
        "pattern": re.compile(r"SK[a-f0-9]{32}"),
        "validator": None,
        "description": "Twilio API Key SID",
        "context_hint": "Look for Auth Token or Account SID nearby",
    },
    {
        "name": "Twilio Account SID",
        "category": CAT_COMMUNICATION,
        "severity": "medium",
        "confidence": "high",
        "pattern": re.compile(r"AC[a-f0-9]{32}"),
        "validator": None,
        "description": "Twilio Account SID — look for corresponding Auth Token nearby",
        "context_hint": "Search for auth_token nearby",
    },
    {
        "name": "SendGrid API Key",
        "category": CAT_COMMUNICATION,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        "validator": None,
        "description": "SendGrid API key — can send emails on behalf of account",
        "context_hint": "Full API access to SendGrid email service",
    },
    {
        "name": "Mailgun API Key",
        "category": CAT_COMMUNICATION,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"key-[a-f0-9]{32}"),
        "validator": None,
        "description": "Mailgun API key",
        "context_hint": "Look for domain configuration nearby",
    },
    {
        "name": "Mailchimp API Key",
        "category": CAT_COMMUNICATION,
        "severity": "medium",
        "confidence": "high",
        "pattern": re.compile(r"[a-f0-9]{32}-us[0-9]{1,2}"),
        "validator": None,
        "description": "Mailchimp API key with datacenter suffix",
        "context_hint": "Datacenter identified by the -usXX suffix",
    },
    {
        "name": "Slack Token",
        "category": CAT_COMMUNICATION,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"xox[bporsae]-[0-9]{10,13}-[A-Za-z0-9-]{20,}"),
        "validator": None,
        "description": "Slack bot/user/app token — check token scopes for access level",
        "context_hint": "Check scopes at api.slack.com/methods/auth.test",
    },
    {
        "name": "Slack Webhook URL",
        "category": CAT_COMMUNICATION,
        "severity": "medium",
        "confidence": "high",
        "pattern": re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"
        ),
        "validator": None,
        "description": "Slack incoming webhook URL — can post messages to channels",
        "context_hint": "Can post messages to a specific Slack channel",
    },

    # === Auth Provider Secrets ============================================

    {
        "name": "GitHub Token",
        "category": CAT_AUTH,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"gh[poustirk]_[A-Za-z0-9_]{36,}"),
        "validator": None,
        "description": "GitHub personal access token, OAuth, or app token",
        "context_hint": "Check token scopes at github.com/settings/tokens",
    },
    {
        "name": "GitHub Fine-Grained Token",
        "category": CAT_AUTH,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
        "validator": None,
        "description": "GitHub fine-grained personal access token",
        "context_hint": "Fine-grained tokens have specific repository and permission scopes",
    },
    {
        "name": "GitLab Token",
        "category": CAT_AUTH,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
        "validator": None,
        "description": "GitLab personal access token",
        "context_hint": "Check token scopes in GitLab settings",
    },
    {
        "name": "Heroku API Key",
        "category": CAT_AUTH,
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:heroku_api_key|HEROKU_API_KEY|heroku[_-]?api[_-]?token)\s*[:=]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']?'
        ),
        "validator": None,
        "description": "Heroku API key (UUID format)",
        "context_hint": "Provides full access to Heroku account",
    },
    {
        "name": "OAuth Client Secret",
        "category": CAT_AUTH,
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:client_secret|CLIENT_SECRET|clientSecret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'
        ),
        "validator": None,
        "description": "OAuth client secret — identify which provider and check if confidential client",
        "context_hint": "Look for client_id and redirect_uri nearby",
    },

    # === CI/CD & DevOps ===================================================

    {
        "name": "NPM Token",
        "category": CAT_CICD,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"npm_[A-Za-z0-9]{36}"),
        "validator": None,
        "description": "NPM authentication token — can publish packages",
        "context_hint": "Can publish and manage NPM packages",
    },
    {
        "name": "Docker Hub Token",
        "category": CAT_CICD,
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(r"dckr_pat_[A-Za-z0-9_-]{24,}"),
        "validator": None,
        "description": "Docker Hub personal access token",
        "context_hint": "Can push/pull Docker images",
    },
    {
        "name": "CircleCI Token",
        "category": CAT_CICD,
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:circle_token|CIRCLE_TOKEN|circleci_token)\s*[:=]\s*["\']?([a-f0-9]{40})["\']?'
        ),
        "validator": None,
        "description": "CircleCI API token",
        "context_hint": "Can access CI/CD pipelines and secrets",
    },
    {
        "name": "Travis CI Token",
        "category": CAT_CICD,
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:travis_token|TRAVIS_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'
        ),
        "validator": None,
        "description": "Travis CI access token",
        "context_hint": "Can trigger builds and access CI settings",
    },

    # === API Keys & Generic Secrets =======================================

    {
        "name": "Mapbox Token",
        "category": CAT_APIKEY,
        "severity": "low",
        "confidence": "high",
        "pattern": re.compile(r"pk\.[A-Za-z0-9]{60}\.[A-Za-z0-9]{20,}"),
        "validator": None,
        "description": "Mapbox public token — check if it has private scope permissions",
        "context_hint": "Verify token scopes at mapbox.com",
    },
    {
        "name": "Sentry DSN",
        "category": CAT_APIKEY,
        "severity": "low",
        "confidence": "high",
        "pattern": re.compile(
            r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+"
        ),
        "validator": None,
        "description": "Sentry DSN — can submit error events to project",
        "context_hint": "Can send error reports to the Sentry project",
    },
    {
        "name": "FCM Server Key",
        "category": CAT_APIKEY,
        "severity": "medium",
        "confidence": "high",
        "pattern": re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
        "validator": None,
        "description": "Firebase Cloud Messaging server key — can push notifications to any device",
        "context_hint": "Server key allows sending push notifications to all app users",
    },
    {
        "name": "Algolia API Key",
        "category": CAT_APIKEY,
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(
            r'(?:algolia_api_key|ALGOLIA_API_KEY|X-Algolia-API-Key)\s*[:=]\s*["\']?([a-f0-9]{32})["\']?'
        ),
        "validator": None,
        "description": "Algolia API key — check if admin key or search-only",
        "context_hint": "Admin keys have write access; search-only keys are less critical",
    },
    {
        "name": "Generic API Key",
        "category": CAT_APIKEY,
        "severity": "medium",
        "confidence": "low",
        "pattern": re.compile(
            r'(?:api[_-]?key|apikey|API[_-]?KEY)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'
        ),
        "validator": None,
        "description": "Generic API key pattern — verify what service this belongs to",
        "context_hint": "Determine the associated service from surrounding context",
    },
    {
        "name": "Generic API Secret",
        "category": CAT_APIKEY,
        "severity": "medium",
        "confidence": "low",
        "pattern": re.compile(
            r'(?:api[_-]?secret|apisecret|API[_-]?SECRET)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'
        ),
        "validator": None,
        "description": "Generic API secret pattern — verify the service",
        "context_hint": "Determine the associated service from surrounding context",
    },
    {
        "name": "Hardcoded Password",
        "category": CAT_APIKEY,
        "severity": "medium",
        "confidence": "low",
        "pattern": re.compile(
            r"""(?:password|passwd|PASSWD|PASSWORD)\s*[:=]\s*["']([^\s"']{8,64})["']"""
        ),
        "validator": _validate_password,
        "description": "Hardcoded password in configuration — verify it's not a placeholder",
        "context_hint": "Check if this is a real credential or a placeholder value",
    },
    {
        "name": "Generic Secret",
        "category": CAT_APIKEY,
        "severity": "medium",
        "confidence": "low",
        "pattern": re.compile(
            r'(?:secret|SECRET|token|TOKEN)[_-]?(?:key|KEY)?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'
        ),
        "validator": None,
        "description": "Generic secret or token — determine the associated service",
        "context_hint": "Identify the service from variable name and surrounding code",
    },
]

# All category constants for UI filtering
ALL_CATEGORIES = [
    CAT_JWT, CAT_CLOUD, CAT_DATABASE, CAT_PAYMENT,
    CAT_COMMUNICATION, CAT_AUTH, CAT_CICD, CAT_APIKEY, CAT_PRIVATE_KEY,
]


# ---------------------------------------------------------------------------
# Scan function
# ---------------------------------------------------------------------------

def scan(text):
    """
    Run all registered patterns against *text*.

    Returns a list of dicts with match info plus surrounding context.
    """
    results = []
    text_len = len(text)

    for entry in patterns:
        for m in entry["pattern"].finditer(text):
            matched = m.group(0)

            # If a validator is defined, skip false positives
            if entry["validator"] is not None:
                try:
                    if not entry["validator"](matched):
                        continue
                except Exception:
                    continue

            # Capture surrounding context
            start = m.start()
            end = m.end()
            ctx_start = max(0, start - 100)
            ctx_end = min(text_len, end + 100)
            context_before = text[ctx_start:start]
            context_after = text[end:ctx_end]

            # Trim to nearest whitespace boundary for cleaner display
            if ctx_start > 0:
                ws_idx = context_before.find(" ")
                if ws_idx >= 0 and ws_idx < len(context_before):
                    context_before = context_before[ws_idx + 1:]

            if ctx_end < text_len:
                ws_idx = context_after.rfind(" ")
                if ws_idx >= 0:
                    context_after = context_after[:ws_idx]

            results.append({
                "match": matched,
                "pattern_name": entry["name"],
                "category": entry["category"],
                "severity": entry["severity"],
                "confidence": entry["confidence"],
                "description": entry["description"],
                "context_hint": entry["context_hint"],
                "start_pos": start,
                "end_pos": end,
                "context_before": context_before,
                "context_after": context_after,
            })
    return results
