"""Settings read from the environment, the same for every app.

They come from the shared secrets file every app's systemd unit loads
(/etc/personal-apps/shared.env, see DEPLOYMENT.md), so there is one place to set
each and nothing per app. Read at import; tests change them with
monkeypatch.setattr(settings, "NAME", value).
"""
import os


def int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# "local" (default) or "production" (set once, droplet-wide, via systemd).
ENV = os.environ.get("APP_ENV", "local")

# --- who is signed in (shared_python.auth) ---------------------------------
# Cloudflare Access signs everyone in before a request reaches an app and attaches
# a signed token. In production both values are REQUIRED (the app refuses every
# request without them). The AUD tag is on each Access application's overview page;
# give several, comma-separated, if more than one application can front the app.
CF_TEAM_DOMAIN = os.environ.get("CF_TEAM_DOMAIN")  # e.g. "yourteam.cloudflareaccess.com"
CF_ACCESS_AUD = os.environ.get("CF_ACCESS_AUD")

# --- a hosted identity provider (shared_python.auth, optional) --------------
# Any provider that issues signed OIDC tokens (JWTs) works, with no code change: set
# these instead. Production accepts a verified Cloudflare Access token, a verified
# provider token, or both (so an app can move across without a flag day).
# The token's `iss` must match this (a trailing slash either way is fine). Keys are
# found at {issuer}/.well-known/openid-configuration unless OIDC_JWKS_URL is given.
OIDC_ISSUER = os.environ.get("OIDC_ISSUER")
OIDC_JWKS_URL = os.environ.get("OIDC_JWKS_URL")
# Comma-separated; checked against the token's `aud` when set (leave unset only if the
# provider issues tokens with no audience; the issuer is checked either way).
OIDC_AUDIENCE = os.environ.get("OIDC_AUDIENCE")
# Signature algorithms accepted; only asymmetric ones (RS*, ES*, PS*, EdDSA) are ever used.
OIDC_ALGORITHMS = os.environ.get("OIDC_ALGORITHMS", "RS256,ES256")
# Which claim holds the person's email. Some providers leave it out of their tokens
# unless asked (a custom claim or token template) - then set it up there.
OIDC_EMAIL_CLAIM = os.environ.get("OIDC_EMAIL_CLAIM", "email")
# Name of the cookie that carries the token (the provider's session cookie). A token
# in an `Authorization: Bearer` header is always accepted too.
OIDC_COOKIE = os.environ.get("OIDC_COOKIE")

# --- letting new people in (shared_python.cloudflare) ----------------------
# The API token needs only "Access: Organizations, Identity Providers, and Groups
# Edit". The group is the one the shared-apps Access policy allows ("Invitees").
CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
CF_INVITEES_GROUP_ID = os.environ.get("CF_INVITEES_GROUP_ID")
# Cloudflare's free Access plan allows 50 people; approving past this is refused.
ACCESS_SEAT_CAP = int_env("ACCESS_SEAT_CAP", 50)

# --- people's own API keys (shared_python.keystore) -------------------------
# Secret the saved keys are encrypted with. REQUIRED in production for saving keys
# (without it the Profile page says saving isn't set up); never change it once keys
# are saved, or they become unreadable. Generate once with:
#   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
KEY_ENCRYPTION_SECRET = os.environ.get("KEY_ENCRYPTION_SECRET")

# --- telling people (shared_python.notify) ---------------------------------
# Each channel is on when its settings are present; use any combination.
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")  # anyone who knows the topic can read it: make it long and random
NTFY_SERVER = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
NTFY_TOKEN = os.environ.get("NTFY_TOKEN")  # only for a protected topic
PUSHOVER_APP_TOKEN = os.environ.get("PUSHOVER_APP_TOKEN")
PUSHOVER_USER_KEY = os.environ.get("PUSHOVER_USER_KEY")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int_env("SMTP_PORT", 587)  # 465 = SSL from the start, anything else = STARTTLS
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM")
NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL")  # where the administrator's email goes
