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
* POST /auth/resend-verification - for someone who signed up but has not confirmed their email: sends the confirmation
  email again (Auth0 only; needs the AUTH0_MGMT_* settings, otherwise the page just doesn't offer it).

The cookie is host-only (each app signs in separately, and the provider's own session
makes the second app's sign-in instant). Its lifetime is the ID token's.

Nothing here is reachable until OIDC_ISSUER and OIDC_CLIENT_ID are set.

One front door for every app (the dashboard): the app that does the sign-in sets
OIDC_COOKIE_DOMAIN (".evancooperman.com") so the session cookie covers every subdomain, and
OIDC_RETURN_HOSTS, the hosts it may send people back to. Every other app sets only
OIDC_LOGIN_URL (the front door's /auth/login): it never sees the client secret, just checks
the cookie (shared_python.auth) and, for signed-out visitors, `redirect_if_signed_out` sends
them to the front door with the page they wanted, and `logout_url` points its Log out link at
the front door's /auth/logout, which ends the session for all of them at once.
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
from urllib.parse import urlencode, urlsplit

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import auth, pages, settings

log = logging.getLogger(__name__)

router = APIRouter()

LOGIN_COOKIE = "oidc_login"  # state, nonce and PKCE verifier while the person is at the provider
LOGIN_COOKIE_SECONDS = 600
VERIFY_COOKIE = "oidc_verify"  # the ID token of someone whose email is not confirmed yet: only ever proves who to resend to
RESEND_EVERY_SECONDS = 60  # per person
RESEND_PER_HOUR = 30  # in all
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


def _return_hosts() -> list:
    raw = settings.OIDC_RETURN_HOSTS
    if raw:
        return [h.strip().lower() for h in raw.split(",") if h.strip()]
    return [] if _secure() else ["localhost", "127.0.0.1"]


def _host_allowed(host: str) -> bool:
    """An exact host, or (for a pattern with a leading dot) any subdomain of it, never the bare domain."""
    host = host.lower()
    for pattern in _return_hosts():
        if pattern.startswith("."):
            if host.endswith(pattern) and len(host) > len(pattern):
                return True
        elif host == pattern:
            return True
    return False


def safe_next(value: Optional[str]) -> str:
    """Where to go after signing in: a path on this site, or a full address on a host the front
    door is allowed to send people back to (OIDC_RETURN_HOSTS). Anything else becomes "/"."""
    if not value or len(value) > 2000 or " " in value or "\\" in value or any(ord(c) < 32 for c in value):
        return "/"
    if value.startswith("/"):
        return "/" if value.startswith("//") else value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or not parts.hostname.isascii():
        return "/"
    if parts.username is not None or parts.password is not None:  # https://good.example@evil.example
        return "/"
    if parts.scheme == "http" and _secure():
        return "/"
    try:
        parts.port  # raises on a malformed port
    except ValueError:
        return "/"
    return value if _host_allowed(parts.hostname) else "/"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _assets_base() -> str:
    if settings.SHARED_ASSETS_BASE:
        return settings.SHARED_ASSETS_BASE.rstrip("/")
    return "https://static.evancooperman.com" if _secure() else "http://127.0.0.1:8070"


def _page(title: str, message: str, status: int = 400, retry_next: str = "/", retry_label: str = "Try signing in again",
          href: Optional[str] = None, extra_html: str = "") -> HTMLResponse:
    """A short explanation in the shared look (these routes have no template of their own). Everything
    that goes into it is escaped (`extra_html` is the one exception: callers pass only markup they wrote)."""
    retry = href or ("/auth/login" + (f"?{urlencode({'next': retry_next})}" if retry_next and retry_next != "/" else ""))
    base, brand = escape(_assets_base()), escape(settings.BRAND_NAME or "")
    body = f"""<!doctype html>
<html lang="en" data-ui="v2">
<head>
{pages.head_html(_assets_base())}
  <title>{brand} - {escape(title)}</title>
</head>
<body>
  <header class="app-header">
    <h1>{brand}</h1>
  </header>
  <main>
    <section class="section">
      <h2>{escape(title)}</h2>
      <p>{escape(message)}</p>
      <p><a class="save-btn" href="{escape(retry)}" data-btn-icon="arrow-right">{escape(retry_label)}</a></p>
{extra_html}
    </section>
  </main>
  <script src="{base}/theme.js"></script>
  <script src="{base}/icons.js"></script>
</body>
</html>
"""
    return HTMLResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


def not_allowed_page(email: str, request: Request) -> HTMLResponse:
    """For someone who is signed in but is not allowed into a private app: say so, and offer to sign out (they
    most likely used the wrong address)."""
    return _page(
        "This app is private",
        f"You're signed in as {email}, which doesn't have access here. If that's the wrong address, sign out and sign in again with the right one.",
        403, retry_label="Sign out", href=logout_url(request) or "/cdn-cgi/access/logout",
    )


def _verify_email_page(email: Optional[str], retry_next: str, can_resend: bool = False, note: str = "",
                       status: int = 403) -> HTMLResponse:
    """Signed in at the provider, but the email address has not been confirmed yet: tell the person what to
    do instead of leaving them at a dead end. (Apps identify people by email, so an unproven address
    never signs anyone in.) With `can_resend` it also offers to send the confirmation email again."""
    where = f"We sent a message to {email}." if email else "We sent you a message."
    resend = ""
    if can_resend:
        resend = (
            f'<form method="post" action="/auth/resend-verification?{escape(urlencode({"next": retry_next}))}">'
            '<button type="submit" class="secondary-btn" data-btn-icon="mail">Resend the email</button></form>'
        )
    return _page(
        "Please verify your email",
        f"{note + ' ' if note else ''}{where} Open it and confirm your address, then sign in again. If you can't find it, check your junk folder.",
        status, retry_next=retry_next, retry_label="I've verified it - sign in again", extra_html=resend,
    )


def _resend_configured() -> bool:
    return bool(settings.AUTH0_MGMT_DOMAIN and settings.AUTH0_MGMT_CLIENT_ID and settings.AUTH0_MGMT_CLIENT_SECRET)


_mgmt_token: dict = {}
_resend_log: dict = {}  # user id -> when we last resent for them
_resend_times: list = []  # when we resent at all, for the hourly cap


def _management_token() -> str:
    """A short-lived Management API token for the one scope we need, kept until shortly before it expires."""
    if _mgmt_token.get("value") and _mgmt_token["expires"] > time.time() + 30:
        return _mgmt_token["value"]
    domain = settings.AUTH0_MGMT_DOMAIN
    reply = requests.post(
        f"https://{domain}/oauth/token",
        json={
            "grant_type": "client_credentials", "client_id": settings.AUTH0_MGMT_CLIENT_ID,
            "client_secret": settings.AUTH0_MGMT_CLIENT_SECRET, "audience": f"https://{domain}/api/v2/",
        },
        timeout=10,
    )
    reply.raise_for_status()
    body = reply.json()
    _mgmt_token.update(value=body["access_token"], expires=time.time() + int(body.get("expires_in", 300)))
    return _mgmt_token["value"]


def _may_resend_now(user_id: str) -> bool:
    now = time.time()
    _resend_times[:] = [t for t in _resend_times if t > now - 3600]
    for key in [k for k, t in _resend_log.items() if t <= now - RESEND_EVERY_SECONDS]:
        del _resend_log[key]
    if user_id in _resend_log or len(_resend_times) >= RESEND_PER_HOUR:
        return False
    _resend_log[user_id] = now
    _resend_times.append(now)
    return True


@router.post("/auth/resend-verification")
def resend_verification(request: Request):
    """Send the confirmation email again to the person whose sign-in just stopped at "please verify your email". Who to
    send it to comes only from the signed ID token that sign-in left in a short-lived cookie, never from the request, so
    nobody can have a message sent to someone else."""
    if not enabled() or not _resend_configured():
        raise HTTPException(status_code=404, detail="Not found")
    token = request.cookies.get(VERIFY_COOKIE)
    try:
        claims = auth.oidc_claims(token, [settings.OIDC_CLIENT_ID]) if token else None
    except HTTPException:
        claims = None
    user_id = claims.get("sub") if claims else None
    if not claims or not isinstance(user_id, str) or not user_id or not auth.email_unverified(claims):
        return _page("That sign-in expired", "Sign in again and we'll take you back to this step.", 400)
    email = claims.get(settings.OIDC_EMAIL_CLAIM)
    email = email if isinstance(email, str) else None
    back = safe_next(request.query_params.get("next"))  # carried through so the person still ends up where they were going
    if not _may_resend_now(user_id):
        return _verify_email_page(email, back, can_resend=True, status=429,
                                  note="That was sent a moment ago, so give it a minute before asking again.")
    try:
        reply = requests.post(
            f"https://{settings.AUTH0_MGMT_DOMAIN}/api/v2/jobs/verification-email",
            json={"user_id": user_id, "client_id": settings.OIDC_CLIENT_ID},
            headers={"Authorization": f"Bearer {_management_token()}"},
            timeout=10,
        )
        reply.raise_for_status()
    except (requests.RequestException, KeyError, ValueError) as exc:
        log.error("Resending the verification email failed: %s", type(exc).__name__)
        _resend_log.pop(user_id, None)  # a failed try should not lock them out for a minute
        return _verify_email_page(email, back, can_resend=True, status=502,
                                  note="We couldn't send it just now, so try again in a minute.")
    return _verify_email_page(email, back, can_resend=True, status=200, note="We've sent it again.")


@router.get("/auth/login")
def login(request: Request, next: str = "/", login_hint: Optional[str] = None, screen_hint: Optional[str] = None):
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
    if screen_hint == "signup":  # open the provider's create-an-account screen (nothing else is passed through)
        params["screen_hint"] = "signup"
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
def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None,
             error_description: Optional[str] = None):
    if not enabled():
        raise HTTPException(status_code=404, detail="Not found")
    if error:
        # The provider said no (e.g. the person cancelled, or may not use this app). Say so plainly;
        # the provider's description can contain anything, so it is only logged.
        log.warning("Identity provider returned an error at sign-in: %s", error[:80])
        if error_description == "email_not_verified":  # a provider rule can deny with this exact code
            return _verify_email_page(None, safe_next((_pending(request) or {}).get("next")))
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
        if auth.email_unverified(claims) and isinstance(claims.get(settings.OIDC_EMAIL_CLAIM), str):
            page = _verify_email_page(claims[settings.OIDC_EMAIL_CLAIM], safe_next(pending.get("next")),
                                      can_resend=_resend_configured())
            if _resend_configured():
                # Kept only so "Resend the email" knows who asked. It is never read as a session: it has its own name,
                # path and lifetime, and an unconfirmed address is refused everywhere a session is checked.
                page.set_cookie(VERIFY_COOKIE, id_token, max_age=max(1, min(LOGIN_COOKIE_SECONDS, int(claims["exp"] - time.time()))),
                                httponly=True, samesite="lax", secure=_secure(), path="/auth")
            page.delete_cookie(LOGIN_COOKIE, path="/auth")
            return page
        auth.email_from_claims(claims)
    except HTTPException as exc:
        return _page("Sign-in didn't complete", str(exc.detail), 401)

    response = RedirectResponse(safe_next(pending.get("next")), status_code=302)
    response.set_cookie(
        auth.oidc_cookie_name(), id_token, max_age=max(1, int(claims["exp"] - time.time())),
        httponly=True, samesite="lax", secure=_secure(), path="/", domain=settings.OIDC_COOKIE_DOMAIN or None,
    )
    response.delete_cookie(LOGIN_COOKIE, path="/auth")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/auth/logout")
def logout(request: Request):
    if not enabled():
        raise HTTPException(status_code=404, detail="Not found")
    id_token = request.cookies.get(auth.oidc_cookie_name() or "")
    path = settings.OIDC_LOGOUT_RETURN_PATH or "/"
    home = _base_url(request) + (path if path.startswith("/") and not path.startswith("//") and "\\" not in path else "/")
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
    response.delete_cookie(auth.oidc_cookie_name(), path="/", domain=settings.OIDC_COOKIE_DOMAIN or None)
    response.headers["Cache-Control"] = "no-store"
    return response


def _front_door() -> Optional[str]:
    """The front door's login address when THIS app should use it (not when this is the front door)."""
    login_url = settings.OIDC_LOGIN_URL
    return login_url if login_url and auth.oidc_configured() else None


def dashboard_url() -> Optional[str]:
    """The dashboard's home page (where people ask for an app they have no account in), when this app sits behind the
    shared front door; None otherwise (Cloudflare Access, or no sign-in configured), when there is nowhere to send them."""
    login_url = _front_door()
    if not login_url:
        return None
    parts = urlsplit(login_url)
    return f"{parts.scheme}://{parts.netloc}/" if parts.scheme in ("http", "https") and parts.netloc else None


def _netloc(host: str, scheme: str) -> str:
    """A host[:port] with the scheme's default port dropped, lowercased, so two spellings compare equal."""
    host = host.lower()
    default = {"http": ":80", "https": ":443"}.get(scheme)
    return host[: -len(default)] if default and host.endswith(default) else host


def _is_front_door_host(request: Request, login_url: str) -> bool:
    """Is this request for the front door itself? Compares the port too: locally every app is
    `localhost` on a different port."""
    parts = urlsplit(login_url)
    mine = request.headers.get("host") or request.url.netloc
    return _netloc(parts.netloc, parts.scheme) == _netloc(mine, request.url.scheme)


def redirect_if_signed_out(request: Request, dev_user_email: str = "") -> Optional[Response]:
    """For an app's HTML pages: a redirect to the sign-in when this visitor isn't signed
    in, or None to carry on. With OIDC_LOGIN_URL set the sign-in is the front door's (and the
    page the visitor wanted rides along as a full address to come back to); otherwise this app's
    own, if configured. Does nothing when neither is, and never locally without a session
    (development uses the configured dev user)."""
    login_url = _front_door()
    if login_url and _is_front_door_host(request, login_url):
        login_url = None  # the front door itself signs people in directly
    if not login_url and not enabled():
        return None
    try:
        auth.request_email(request, dev_user_email)
        return None
    except HTTPException as exc:
        if exc.status_code != 401:
            return None
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    if login_url:
        host = request.headers.get("host") or request.url.netloc
        wanted = f"{'https' if _secure() else request.url.scheme}://{host}{target}"
        joiner = "&" if "?" in login_url else "?"
        return RedirectResponse(f"{login_url}{joiner}{urlencode({'next': wanted})}", status_code=302)
    return RedirectResponse(f"/auth/login?{urlencode({'next': safe_next(target)})}", status_code=302)


def logout_url(request: Request) -> Optional[str]:
    """Where this app's Log out link should go, or None for the page's default (Cloudflare
    Access). Someone who came through Cloudflare logs out there; otherwise it is the front
    door's /auth/logout (ending the session for every app), or this app's own."""
    if request.headers.get(auth.JWT_HEADER):
        return None
    login_url = _front_door()
    if login_url and not _is_front_door_host(request, login_url):
        base = login_url.split("?")[0].rstrip("/")
        return (base[: -len("/login")] if base.endswith("/login") else base.rsplit("/", 1)[0]) + "/logout"
    return "/auth/logout" if enabled() else None
