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

# --- letting new people in (shared_python.cloudflare) ----------------------
# The API token needs only "Access: Organizations, Identity Providers, and Groups
# Edit". The group is the one the shared-apps Access policy allows ("Invitees").
CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
CF_INVITEES_GROUP_ID = os.environ.get("CF_INVITEES_GROUP_ID")
# Cloudflare's free Access plan allows 50 people; approving past this is refused.
ACCESS_SEAT_CAP = int_env("ACCESS_SEAT_CAP", 50)

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
