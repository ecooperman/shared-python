"""Letting an email through Cloudflare Access's login gate.

Everyone reaches the app through Cloudflare Access, and the shared-apps Access
policy allows an "Invitees" group of email addresses. Approving an invite adds
the person's email to that group over Cloudflare's API, so they can sign in
(with a one-time PIN sent to that address) without anyone touching the
dashboard.

Updating a group replaces its whole rule list, so we read it, add the email and
send everything back, then check the reply really contains the email. Without
the settings (see settings.py) this does nothing locally and refuses in
production, so an approval is never recorded for a person who still can't get
in.
"""
import logging
import threading

import requests

from . import settings

log = logging.getLogger(__name__)

API = "https://api.cloudflare.com/client/v4"

# Two approvals at once would each read the group, add their own email and
# write it back - the second write would drop the first. One at a time.
_lock = threading.Lock()


class CloudflareError(Exception):
    """Cloudflare refused or didn't answer; the message is safe to show the administrator."""


class NotConfigured(CloudflareError):
    pass


class SeatCapReached(CloudflareError):
    pass


def configured() -> bool:
    return bool(settings.CF_API_TOKEN and settings.CF_ACCOUNT_ID and settings.CF_INVITEES_GROUP_ID)


def _call(method: str, url: str, **kwargs) -> dict:
    try:
        resp = requests.request(
            method, url, headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"}, timeout=10, **kwargs
        )
        body = resp.json()
    except (requests.RequestException, ValueError) as exc:
        # Not str(exc): a request error can echo the URL, and nothing here needs more than the type.
        log.warning("Cloudflare API call failed: %s", type(exc).__name__)
        raise CloudflareError("Couldn't reach Cloudflare - try again in a moment")
    if not resp.ok or not body.get("success"):
        errors = body.get("errors") or []
        message = errors[0].get("message") if errors and isinstance(errors[0], dict) else None
        log.warning("Cloudflare API refused (%s): %s", resp.status_code, message)
        raise CloudflareError(f"Cloudflare refused the request: {message or resp.status_code}")
    return body["result"]


def _emails(rules) -> set:
    return {
        rule["email"]["email"].lower()
        for rule in rules or []
        if isinstance(rule, dict) and isinstance(rule.get("email"), dict) and rule["email"].get("email")
    }


def _group_url() -> str:
    return f"{API}/accounts/{settings.CF_ACCOUNT_ID}/access/groups/{settings.CF_INVITEES_GROUP_ID}"


def is_let_in(email: str, admin_emails):
    """Whether Cloudflare currently lets this email through the login gate:
    True for an administrator (they get in by their own policy; the caller says who
    those are, since that differs per app) or anyone in
    the Invitees group, False for everyone else. None when there's nothing to
    ask because Cloudflare isn't configured (local development, or before it's
    set up) - the caller goes by what it knows itself. Read-only. Raises
    CloudflareError if Cloudflare can't be asked."""
    if not configured():
        return None
    if email in admin_emails:
        return True
    return email in _emails(_call("get", _group_url()).get("include"))


def allow_email(email: str) -> None:
    """Make sure `email` is in the Invitees group. Already being there is fine.
    Raises NotConfigured (production only), SeatCapReached or CloudflareError."""
    if not configured():
        if settings.ENV == "production":
            log.error("CF_API_TOKEN, CF_ACCOUNT_ID and CF_INVITEES_GROUP_ID must be set to approve invites")
            raise NotConfigured("Cloudflare isn't set up on the server, so nobody can be let in yet")
        log.info("Cloudflare isn't configured; not adding %s to the allowed group (local mode)", email)
        return

    url = _group_url()
    with _lock:
        group = _call("get", url)
        include = group.get("include") or []
        present = _emails(include)
        if email in present:
            return
        if len(present) >= settings.ACCESS_SEAT_CAP:
            raise SeatCapReached(
                f"The allowed group already has {len(present)} people (the limit is {settings.ACCESS_SEAT_CAP}) - "
                "remove someone in Cloudflare first"
            )
        updated = _call(
            "put",
            url,
            json={
                "name": group["name"],
                "include": include + [{"email": {"email": email}}],
                "exclude": group.get("exclude") or [],
                "require": group.get("require") or [],
            },
        )
        if email not in _emails(updated.get("include")):
            raise CloudflareError("Cloudflare accepted the change but the email isn't in the group")
