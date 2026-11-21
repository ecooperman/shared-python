"""Tell the dashboard when someone's access to this app changes.

The dashboard remembers, per person, which apps they may open (it draws every app's menu from that, see dashboard/app/access.py) and drops
the answer itself whenever IT changes someone's access. A change made inside an app (its own Users page, an in-app invite, a removal)
would otherwise show only when the remembered answer runs out; so each app calls `install(models.User)` once and, whenever a user row is
added or its `status` changes, the dashboard is told (after the change is committed, never before) and forgets that person.

Best effort and in the background: a thread posts to settings.DASHBOARD_API_BASE (the dashboard's own process on this machine) and any
failure is only logged, so a change of access never waits on, or fails because of, the dashboard. Nothing is sent when that setting is
empty (locally and in tests). The message is just the email address, to an address that refuses anything arriving through the internet."""
import logging
import threading

import requests
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session, object_session

from . import settings

log = logging.getLogger(__name__)

PATH = "/internal/access-changed"
_PENDING = "access_changed_emails"  # kept on the session until its transaction ends
_session_hooks_installed = False


def _post(email: str) -> None:
    base = settings.DASHBOARD_API_BASE
    if not base:
        return
    try:
        requests.post(base.rstrip("/") + PATH, json={"email": email}, timeout=2)
    except Exception as exc:  # noqa: BLE001 - telling the dashboard must never matter to the change itself
        log.warning("Could not tell the dashboard that access changed: %s", type(exc).__name__)


def _tell(emails) -> None:
    if not settings.DASHBOARD_API_BASE:
        return
    for email in emails:
        threading.Thread(target=_post, args=(email,), daemon=True).start()


def _note(target) -> None:
    session = object_session(target)
    email = getattr(target, "email", None)
    if session is not None and email:
        session.info.setdefault(_PENDING, set()).add(email)


def install(user_model) -> None:
    """Watch `user_model` (an app's users table: needs `email` and `status`). Call once per app, at import."""
    global _session_hooks_installed
    event.listen(user_model, "after_insert", lambda mapper, connection, target: _note(target))

    def updated(mapper, connection, target):
        if inspect(target).attrs.status.history.has_changes():
            _note(target)

    event.listen(user_model, "after_update", updated)
    if not _session_hooks_installed:
        _session_hooks_installed = True
        event.listen(Session, "after_commit", lambda session: _tell(session.info.pop(_PENDING, ())))
        event.listen(Session, "after_soft_rollback", lambda session, previous: session.info.pop(_PENDING, None))
