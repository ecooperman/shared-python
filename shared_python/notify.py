"""Telling the administrator something needs them, over whichever channels are
set up (see settings.py): ntfy and Pushover (phone push) and email. A channel
with no settings is skipped, and one failing never stops the others or the
request that triggered it - this runs after the response is sent.
"""
import logging
import smtplib
from email.message import EmailMessage
from typing import Optional

import requests

from . import settings

log = logging.getLogger(__name__)

TIMEOUT = 10


def _ntfy(title: str, message: str, link: Optional[str]) -> None:
    if not settings.NTFY_TOPIC:
        return
    payload = {"topic": settings.NTFY_TOPIC, "title": title, "message": message}
    if link:
        payload["click"] = link
    headers = {"Authorization": f"Bearer {settings.NTFY_TOKEN}"} if settings.NTFY_TOKEN else {}
    requests.post(settings.NTFY_SERVER, json=payload, headers=headers, timeout=TIMEOUT).raise_for_status()


def _pushover(title: str, message: str, link: Optional[str]) -> None:
    if not (settings.PUSHOVER_APP_TOKEN and settings.PUSHOVER_USER_KEY):
        return
    data = {"token": settings.PUSHOVER_APP_TOKEN, "user": settings.PUSHOVER_USER_KEY, "title": title, "message": message}
    if link:
        data["url"] = link
    requests.post("https://api.pushover.net/1/messages.json", data=data, timeout=TIMEOUT).raise_for_status()


def describe_failure(exc: Exception) -> str:
    """What to log about a failed send. Normally only the exception's type
    (some libraries put a URL or credentials in the message), but an SMTP
    server's reply is its own text - "550 domain not verified" - never our
    credentials, and without it a refusal can't be told from another one."""
    if isinstance(exc, smtplib.SMTPResponseException):
        reply = exc.smtp_error.decode("utf-8", "replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
        return f"{type(exc).__name__} {exc.smtp_code} {_one_line(reply)[:200]}"
    return type(exc).__name__


def _one_line(text: str) -> str:
    """Header text must be one line: a newline in a list name would otherwise
    be refused (or worse, start a new header)."""
    return " ".join(str(text).split())


def send_email(to: str, subject: str, body: str, html: Optional[str] = None, reply_to: Optional[str] = None) -> bool:
    """One email through the configured SMTP server: plain text, plus a rich
    (HTML) version when `html` is given, and replies going to `reply_to` when
    given (for mail sent on a person's behalf). Does nothing (and says so)
    without a server. Raises on a failed send - callers that must not fail wrap
    it (see notify() and tell_given_access())."""
    if not (settings.SMTP_HOST and settings.SMTP_FROM):
        return False
    msg = EmailMessage()
    msg["Subject"] = _one_line(subject)
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = _one_line(reply_to)
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    if settings.SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=TIMEOUT)
    else:
        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=TIMEOUT)
    with server:
        if settings.SMTP_PORT != 465:
            server.starttls()
        if settings.SMTP_USERNAME:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD or "")
        server.send_message(msg)
    return True


def _email(title: str, message: str, link: Optional[str]) -> None:
    """The administrator's email channel."""
    if settings.NOTIFY_EMAIL:
        send_email(settings.NOTIFY_EMAIL, title, f"{message}\n\n{link}" if link else message)


CHANNELS = {"ntfy": _ntfy, "pushover": _pushover, "email": _email}


def notify(title: str, message: str, link: Optional[str] = None) -> None:
    for name, send in CHANNELS.items():
        try:
            send(title, message, link)
        except Exception as exc:  # noqa: BLE001 - any failure of one channel must not reach the caller
            # The type only: some libraries put the URL or credentials in the message.
            log.warning("Notification via %s failed: %s", name, describe_failure(exc))


def invite_requested(app_name: str, inviter_email: str, invitee_email: str, role: Optional[str], admin_url: str) -> None:
    """Tell the administrator someone asked for a new person to be let in.
    `app_name` ("Lists") and `admin_url` (the app's Invites page) are the app's own.
    `role` is what they'd get on a shared thing; None for an invite to the app itself."""
    what = "" if role is None else f" (can {'edit' if role == 'edit' else 'view'})"
    notify(
        f"{app_name}: invite waiting for approval",
        f"{inviter_email} wants to let {invitee_email} in{what}.",
        admin_url,
    )


def _sign_in_lines(to: str) -> list:
    """For someone who has never signed in here: Cloudflare's sign-in page can't be
    pre-filled from a link, so name the address to type there - it has to be this
    one, the one they were let in as."""
    return [
        "",
        "The first time you open it you'll be asked to sign in. Enter this email address:",
        "",
        f"    {to}",
        "",
        "and a one-time PIN will be sent to it - there is no password to set up.",
    ]


def tell_given_access(
    to: str,
    inviter_email: str,
    kind: str,
    name: str,
    open_url: Optional[str],
    role: str,
    new_person: bool,
    app_name: str,
) -> None:
    """Tell someone they've been given access to a list/trip/... - by email only,
    since they may never have used the app and can't be expected to have anything
    set up for push. `kind` ("list", "trip") and `name` say what was shared,
    `open_url` is a link straight to it (or None), `app_name` is for the wording.
    `new_person`: they haven't signed in here before, so say how (Cloudflare emails
    them a one-time PIN). Best effort, like notify(): a failure is logged and never
    reaches the caller."""
    can = "edit" if role == "edit" else "view"
    lines = [f'{inviter_email} gave you access to the {kind} "{name}" in {app_name} - you can {can} it.']
    if open_url:
        lines += ["", f"Open it here: {open_url}"]
    if new_person:
        lines += _sign_in_lines(to)
    try:
        send_email(to, f'{inviter_email} shared "{name}" with you', "\n".join(lines))
    except Exception as exc:  # noqa: BLE001 - never fail the approval or the add that triggered this
        log.warning("Telling the new person by email failed: %s", describe_failure(exc))


def tell_let_in(to: str, inviter_email: str, app_name: str, open_url: Optional[str]) -> None:
    """Tell someone they've been let into the app itself (an invite to the app, not
    to one shared thing) - by email, with how to sign in, since they have never used
    it. Best effort, like tell_given_access(): a failure is logged, never raised."""
    lines = [f"{inviter_email} invited you to {app_name}, and an administrator has approved it."]
    if open_url:
        lines += ["", f"Open it here: {open_url}"]
    lines += _sign_in_lines(to)
    try:
        send_email(to, f"{inviter_email} invited you to {app_name}", "\n".join(lines))
    except Exception as exc:  # noqa: BLE001
        log.warning("Telling the new person by email failed: %s", describe_failure(exc))
