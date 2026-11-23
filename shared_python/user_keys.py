"""A person's own API keys, kept once on the dashboard, as the apps use them.

Each person saves a key for a service (Anthropic, Google Maps, Jina) once, on their Profile page on the dashboard. An app that needs it asks the
dashboard (`GET /internal/keys/...` on settings.DASHBOARD_API_BASE, this machine only) and forwards THE PERSON'S OWN sign-in cookie, so an app can
only ever get the key of someone who is signed in and using it right now, never everyone's. The key is held in memory only: nothing is stored in
the app.

    user_keys.install(app)               # once, in the app: remembers the request's sign-in cookie for the length of the request
    key = user_keys.fetch("anthropic")   # None if they have not saved one; HTTP 503 if the dashboard cannot be reached
    have = user_keys.status()            # {provider: {"last4", "added_at"}} for every key they saved (never the keys)

Work that carries on after the request (a thread, a queue) must take the person's session WITH it, because a thread does not inherit the
request's context:

    session = user_keys.current()        # in the request; call session.get("anthropic") here so the key is fetched while they are signed in
    ...
    with user_keys.use(session):         # in the worker
        key = user_keys.fetch("anthropic")   # answered from what was already fetched

Locally there is no sign-in cookie: the dashboard answers for its dev user, the same person the app sees. In production a request with no
cookie at all (a token-only door) simply has no key available: nothing is asked of the dashboard."""
import contextvars
import logging
from contextlib import contextmanager
from typing import Dict, Optional

import requests
from fastapi import HTTPException, Request

from . import auth, settings

log = logging.getLogger(__name__)

TIMEOUT = 5
_DOWN = "Couldn't reach the place your keys are kept just now. Please try again in a moment."


class KeySession:
    """One person's sign-in cookie, and the keys already fetched with it."""

    def __init__(self, cookie: Optional[str] = None):
        self.cookie = cookie  # "name=value", or None (locally, or signed out)
        self._keys: Dict[str, Optional[str]] = {}
        self._status: Optional[dict] = None

    def _get(self, path: str) -> Optional[dict]:
        base = settings.DASHBOARD_API_BASE
        if not base:
            raise HTTPException(status_code=503, detail="Saved keys aren't set up on this server.")
        headers = {"Cookie": self.cookie} if self.cookie else {}
        try:
            reply = requests.get(base.rstrip("/") + path, headers=headers, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as exc:
            log.warning("Asking the dashboard for a key failed: %s", type(exc).__name__)
            raise HTTPException(status_code=503, detail=_DOWN)
        if reply.status_code == 404:
            return None  # signed in, nothing saved
        if reply.status_code == 401:
            raise HTTPException(status_code=401, detail="Please sign in again.")
        if reply.status_code != 200:
            log.warning("The dashboard answered %s when asked for a key", reply.status_code)
            raise HTTPException(status_code=503, detail=_DOWN)
        try:
            return reply.json()
        except ValueError:
            raise HTTPException(status_code=503, detail=_DOWN)

    def _anonymous(self) -> bool:
        """In production a request with no sign-in cookie (an app's token-only door, such as the Chrome extension's push) has no person to fetch a
        key for: nothing is asked of the dashboard and no key is available. (Locally there is never a cookie and the dashboard answers for its
        dev user, the same person the app sees.)"""
        return self.cookie is None and settings.ENV == "production"

    def get(self, provider: str) -> Optional[str]:
        if self._anonymous():
            return None
        if provider not in self._keys:
            found = self._get(f"/internal/keys/{provider}")
            self._keys[provider] = found.get("key") if isinstance(found, dict) else None
        return self._keys[provider]

    def status(self) -> dict:
        if self._anonymous():
            return {}
        if self._status is None:
            found = self._get("/internal/keys")
            self._status = (found or {}).get("keys", {}) if isinstance(found, dict) else {}
        return self._status


_current: contextvars.ContextVar = contextvars.ContextVar("user_keys_session", default=None)


def install(app) -> None:
    """Remember each request's sign-in cookie (only that one cookie), for fetch() and status() while the request is handled."""

    @app.middleware("http")
    async def remember_the_sign_in(request: Request, call_next):
        name = auth.oidc_cookie_name()
        value = request.cookies.get(name) if name else None
        token = _current.set(KeySession(f"{name}={value}" if value else None))
        try:
            return await call_next(request)
        finally:
            _current.reset(token)


def current() -> Optional[KeySession]:
    return _current.get()


@contextmanager
def use(session: Optional[KeySession]):
    """Run as this person's session (in a thread, where the request's context is gone)."""
    token = _current.set(session)
    try:
        yield session
    finally:
        _current.reset(token)


def fetch(provider: str) -> Optional[str]:
    session = _current.get()
    return session.get(provider) if session is not None else None


def status() -> dict:
    session = _current.get()
    return session.status() if session is not None else {}
