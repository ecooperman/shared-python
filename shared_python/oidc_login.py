"""Signing people in through a hosted identity provider (any OIDC issuer).

Standard authorization-code flow with PKCE, found through the issuer's discovery
document, so the provider is only settings (see settings.py) and no vendor SDK is
involved. An app mounts the router once:

    from shared_python import oidc_login
    app.include_router(oidc_login.router)

and sends signed-out visitors to /auth/login (see `redirect_if_signed_out`).

* GET /auth/login?next=/path[&login_hint=email] - sends the browser to the provider.
* GET /auth/callback - the provider sends them back with a code; it is exchanged for an
  ID token, which is verified and then kept in an httponly cookie. The same cookie is
  what `shared_python.auth.request_email` reads on every later request.
* GET /auth/logout - clears the cookie and ends the provider's session too.

The cookie is host-only (each app signs in separately, and the provider's own session
makes the second app's sign-in instant). Its lifetime is the ID token's.

Nothing here is reachable until OIDC_ISSUER and OIDC_CLIENT_ID are set.
"""
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from html import escape
from typing import Optional
from urllib.parse import urlencode

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import auth, settings

log = logging.getLogger(__name__)

router = APIRouter()

LOGIN_COOKIE = "oidc_login"  # state, nonce and PKCE verifier while the person is at the provider
LOGIN_COOKIE_SECONDS = 600
_DISCOVERY_SECONDS = 3600
_discovery_cache: dict = {}


def enabled() -> bool:
    return bool(auth.oidc_configured() and settings.OIDC_CLIENT_ID)


def _discovery() -> dict:
    """The primary issuer's discovery document (cached)."""
    issuer = auth.oidc_issuers()[0]
    cached = _discovery_cache.get(issuer)
    if cached and time.time() - cached[0] < _DISCOVERY_SECONDS:
        return cached[1]
    resp = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    resp.raise_for_status()
    doc = resp.json()
    _discovery_cache[issuer] = (time.time(), doc)
    return doc


def _secure() -> bool:
    return settings.ENV == "production"


def _base_url(request: Request) -> str:
    """This app's public address. The host is whatever the browser asked for; the
    provider only honours redirect addresses registered with it, so a forged Host
    header cannot send anyone anywhere else."""
    scheme = "https" if _secure() else request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def safe_next(value: Optional[str]) -> str:
    """Where to go after signing in: a path on this site, never another address."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value and "\n" not in value:
        return value
    return "/"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _page(title: str, message: str, status: int = 400) -> HTMLResponse:
    """A plain explanation (these routes have no template of their own)."""
    body = (
        f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{escape(title)}</title>"
        f"<body style='font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem'>"
        f"<h1>{escape(title)}</h1><p>{escape(message)}</p><p><a href='/auth/login'>Try signing in again</a></p></body>"
    )
    return HTMLResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


@router.get("/auth/login")
def login(request: Request, next: str = "/", login_hint: Optional[str] = None):
    if not enabled():
        raise HTTPException(status_code=404, detail="Not found")
    try:
        endpoint = _discovery()["authorization_endpoint"]
    except (requests.RequestException, KeyError, ValueError) as exc:
        log.error("Could not read the identity provider's discovery document: %s", type(exc).__name__)
        return _page("Sign-in is unavailable", "The sign-in service could not be reached. Try again in a minute.", 503)
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": _base_url(request) + "/auth/callback",
        "scope": settings.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
    }
    if login_hint and len(login_hint) < 255:
        params["login_hint"] = login_hint
    pending = {"state": state, "nonce": nonce, "verifier": verifier, "next": safe_next(next)}
    response = RedirectResponse(f"{endpoint}?{urlencode(params)}", status_code=302)
    response.set_cookie(
        LOGIN_COOKIE, _b64(json.dumps(pending).encode()), max_age=LOGIN_COOKIE_SECONDS,
        httponly=True, samesite="lax", secure=_secure(), path="/auth",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _pending(request: Request) -> Optional[dict]:
    raw = request.cookies.get(LOGIN_COOKIE)
    if not raw:
        return None
    try:
        data = json.loads(_unb64(raw))
        return data if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError):
        return None


@router.get("/auth/callback")
def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    if not enabled():
        raise HTTPException(status_code=404, detail="Not found")
    if error:
        # The provider said no (e.g. the person cancelled, or may not use this app). Say so plainly;
        # the provider's description can contain anything, so it is only logged.
        log.warning("Identity provider returned an error at sign-in: %s", error[:80])
        return _page("Sign-in didn't complete", "The sign-in was cancelled or refused.", 400)
    pending = _pending(request)
    if not pending or not code or not state or not hmac.compare_digest(str(pending.get("state", "")), state):
        return _page("That sign-in expired", "The sign-in took too long or was started somewhere else.", 400)

    try:
        token_endpoint = _discovery()["token_endpoint"]
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _base_url(request) + "/auth/callback",
            "client_id": settings.OIDC_CLIENT_ID,
            "code_verifier": pending.get("verifier", ""),
        }
        if settings.OIDC_CLIENT_SECRET:
            form["client_secret"] = settings.OIDC_CLIENT_SECRET
        reply = requests.post(token_endpoint, data=form, timeout=10)
        tokens = reply.json() if reply.status_code == 200 else {}
    except (requests.RequestException, KeyError, ValueError) as exc:
        log.error("Sign-in token exchange failed: %s", type(exc).__name__)
        return _page("Sign-in is unavailable", "The sign-in service could not be reached. Try again in a minute.", 503)
    id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
    if not id_token:
        log.warning("Sign-in token exchange was refused (status %s)", getattr(reply, "status_code", "?"))
        return _page("Sign-in didn't complete", "The sign-in service refused the request.", 400)

    try:
        claims = auth.oidc_claims(id_token, [settings.OIDC_CLIENT_ID])
        if not hmac.compare_digest(str(claims.get("nonce", "")), str(pending.get("nonce", ""))):
            raise HTTPException(status_code=401, detail="Sign-in token was not issued for this sign-in")
        auth.email_from_claims(claims)
    except HTTPException as exc:
        return _page("Sign-in didn't complete", str(exc.detail), 401)

    response = RedirectResponse(safe_next(pending.get("next")), status_code=302)
    response.set_cookie(
        auth.oidc_cookie_name(), id_token, max_age=max(1, int(claims["exp"] - time.time())),
        httponly=True, samesite="lax", secure=_secure(), path="/",
    )
    response.delete_cookie(LOGIN_COOKIE, path="/auth")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/auth/logout")
def logout(request: Request):
    if not enabled():
        raise HTTPException(status_code=404, detail="Not found")
    id_token = request.cookies.get(auth.oidc_cookie_name() or "")
    home = _base_url(request) + "/"
    target = home
    try:
        end_session = _discovery().get("end_session_endpoint")
    except (requests.RequestException, ValueError):
        end_session = None
    if end_session:
        params = {"post_logout_redirect_uri": home, "client_id": settings.OIDC_CLIENT_ID}
        if id_token:
            params["id_token_hint"] = id_token
        target = f"{end_session}?{urlencode(params)}"
    response = RedirectResponse(target, status_code=302)
    response.delete_cookie(auth.oidc_cookie_name(), path="/")
    response.headers["Cache-Control"] = "no-store"
    return response


def redirect_if_signed_out(request: Request, dev_user_email: str = "") -> Optional[Response]:
    """For an app's HTML pages: a redirect to the sign-in when this visitor isn't signed
    in, or None to carry on. Does nothing unless the sign-in flow is configured, and
    never locally without a session (development uses the configured dev user)."""
    if not enabled():
        return None
    try:
        auth.request_email(request, dev_user_email)
        return None
    except HTTPException as exc:
        if exc.status_code != 401:
            return None
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse(f"/auth/login?{urlencode({'next': safe_next(target)})}", status_code=302)
