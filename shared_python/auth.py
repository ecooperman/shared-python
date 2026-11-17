"""Who is making this request, from Cloudflare Access or a hosted identity provider.

There are no passwords or sign-up forms in the apps: every request carries a signed
token saying who is asking, and this verifies it. Each app then turns the email into
its own user row.

Two kinds of token are understood, either or both:

* Cloudflare Access's (Cf-Access-Jwt-Assertion), verified against Cloudflare's
  published keys (needs CF_TEAM_DOMAIN + CF_ACCESS_AUD, see settings.py).
* Any OIDC provider's (needs OIDC_ISSUER and friends, see settings.py), from an
  `Authorization: Bearer` header or the provider's session cookie. Which provider it
  is is only settings: issuer, audience, cookie name, email claim.

Production refuses every request when neither is configured, rather than trusting the
plain email header: that header is only set by Access, and a hostname that bypasses
Access (or is misconfigured) lets a visitor send any value they like, which would mean
signing in as anyone.
"""
import logging
import threading
import time
from contextlib import asynccontextmanager
from typing import Optional

import jwt
import requests
from fastapi import HTTPException, Request

from . import settings

log = logging.getLogger(__name__)

EMAIL_HEADER = "cf-access-authenticated-user-email"
JWT_HEADER = "cf-access-jwt-assertion"

_jwks_client: Optional[jwt.PyJWKClient] = None


def _cloudflare_key_client() -> jwt.PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        # Forgive a pasted "https://" or trailing slash - it's just a hostname.
        domain = settings.CF_TEAM_DOMAIN.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        _jwks_client = jwt.PyJWKClient(f"https://{domain}/cdn-cgi/access/certs", lifespan=3600)
    return _jwks_client


def _signing_key(token: str):
    """Cloudflare's public key for this token (cached by PyJWKClient)."""
    return _cloudflare_key_client().get_signing_key_from_jwt(token).key


def _email_from_verified_token(token: str) -> str:
    try:
        claims = jwt.decode(
            token,
            _signing_key(token),
            algorithms=["RS256"],
            audience=[aud.strip() for aud in settings.CF_ACCESS_AUD.split(",") if aud.strip()],
            options={"require": ["exp", "aud"]},
        )
    except jwt.PyJWTError as exc:
        log.warning("Rejected Cloudflare Access token: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid sign-in token")
    email = claims.get("email")
    if not email:
        # e.g. a service token - it identifies a machine, not a person.
        raise HTTPException(status_code=401, detail="Sign-in token has no email")
    return email


# --- a hosted identity provider (any OIDC issuer) ---------------------------------

# issuer + explicit keys URL -> that issuer's key client (keys cached by PyJWKClient)
_oidc_client: Optional[dict] = None

# Only asymmetric algorithms are ever accepted: allowing HS256 would let anyone who
# knows the (public) key sign tokens with it.
_ASYMMETRIC = ("RS", "ES", "PS", "EdDSA")


def oidc_issuers() -> list:
    """The configured issuers, normalized (no trailing slash). OIDC_ISSUER may list
    several, comma-separated, so a move between providers can run both side by side;
    the first one is where people are sent to sign in."""
    return [i.strip().rstrip("/") for i in (settings.OIDC_ISSUER or "").split(",") if i.strip()]


def oidc_configured() -> bool:
    return bool(oidc_issuers())


def front_door_active() -> bool:
    """This app signs people in through the shared front door (the dashboard) rather than Cloudflare Access:
    OIDC_LOGIN_URL and an issuer are set. Then the Cloudflare login gate is not what lets people in."""
    return bool(settings.OIDC_LOGIN_URL) and oidc_configured()


def oidc_cookie_name() -> Optional[str]:
    """The cookie the signed-in person's token travels in: OIDC_COOKIE if a provider
    delivers one, else our own (when this app does the sign-in itself)."""
    return settings.OIDC_COOKIE or ("oidc_session" if (settings.OIDC_CLIENT_ID or settings.OIDC_LOGIN_URL) else None)


def _oidc_algorithms() -> list:
    wanted = [a.strip() for a in settings.OIDC_ALGORITHMS.split(",") if a.strip()]
    return [a for a in wanted if a.startswith(_ASYMMETRIC)]


def _oidc_jwks_url(issuer: str) -> str:
    """Where the provider publishes its signing keys: given explicitly (one issuer
    only), or found through the issuer's standard discovery document."""
    if settings.OIDC_JWKS_URL and len(oidc_issuers()) == 1:
        return settings.OIDC_JWKS_URL
    resp = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    resp.raise_for_status()
    return resp.json()["jwks_uri"]


def _issuer_for(token: str, issuers: list) -> str:
    """Which configured issuer a token claims to come from (its signature is checked
    afterwards, against that issuer's keys). A token naming none of them gets the
    first, whose checks then refuse it."""
    try:
        claimed = jwt.decode(token, options={"verify_signature": False}).get("iss")
    except jwt.PyJWTError:
        claimed = None
    if isinstance(claimed, str) and claimed.rstrip("/") in issuers:
        return claimed.rstrip("/")
    return issuers[0]


def _oidc_key_client(issuer: str) -> jwt.PyJWKClient:
    """This issuer's key client (made once, then reused: it caches the keys for an hour)."""
    global _oidc_client
    if _oidc_client is None:
        _oidc_client = {}
    cache_key = (issuer, settings.OIDC_JWKS_URL)
    client = _oidc_client.get(cache_key)
    if client is None:
        client = _oidc_client[cache_key] = jwt.PyJWKClient(_oidc_jwks_url(issuer), lifespan=3600)
    return client


def _oidc_signing_key(token: str):
    """The provider's public key for this token (keys cached by PyJWKClient)."""
    return _oidc_key_client(_issuer_for(token, oidc_issuers())).get_signing_key_from_jwt(token).key


# --- keeping the keys warm -----------------------------------------------------------------------------------------------
# Checking a sign-in needs the provider's public keys, and finding them takes two web calls (its discovery document, then the
# keys). Without this the FIRST person to load a page after every restart waits for both, in every app separately (and the
# dashboard, which asks each app whether they have an account, can give up on a slow one). So each app fetches them in the
# background as it starts, and again before the hour they are cached for runs out. Never fatal: if the provider can't be
# reached, the first real request simply does what it always did.

WARM_EVERY_SECONDS = 50 * 60  # the keys are cached for 60 minutes (lifespan above)


def warm_up(refresh: bool = False) -> None:
    """Fetch (or, with refresh, re-fetch) the signing keys for every configured provider now."""
    if settings.CF_TEAM_DOMAIN and settings.CF_ACCESS_AUD:
        try:
            _cloudflare_key_client().get_jwk_set(refresh=refresh)
        except Exception as exc:  # noqa: BLE001 - warming is best effort
            log.warning("Could not pre-fetch Cloudflare's keys: %s", type(exc).__name__)
    for issuer in oidc_issuers():
        try:
            _oidc_key_client(issuer).get_jwk_set(refresh=refresh)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not pre-fetch the sign-in keys for %s: %s", issuer, type(exc).__name__)


def _keep_warm() -> None:
    warm_up()
    while True:
        time.sleep(WARM_EVERY_SECONDS)
        warm_up(refresh=True)


def warm_up_on_start(app) -> None:
    """Call once per app: when the app starts, begin fetching (and keeping fresh) the sign-in keys in a background thread, so
    starting is not slowed and nobody's first page waits for them. Wraps the app's lifespan (the way current Starlette and
    FastAPI run start-up code), keeping whatever lifespan or start-up handlers the app already has."""
    previous = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(inner_app):
        threading.Thread(target=_keep_warm, name="sign-in-key-warm-up", daemon=True).start()
        async with previous(inner_app) as state:
            yield state

    app.router.lifespan_context = lifespan


def oidc_claims(token: str, audience: list) -> dict:
    """The verified claims of a provider token: signature, expiry, issuer (any
    configured one) and, when given, audience. 401 if anything is wrong."""
    algorithms = _oidc_algorithms()
    if not algorithms:
        log.error("OIDC_ALGORITHMS has no asymmetric algorithm - refusing provider tokens")
        raise HTTPException(status_code=503, detail="Sign-in is not configured on the server")
    issuers = oidc_issuers()
    issuer = _issuer_for(token, issuers)
    required = ["exp", "iss"] + (["aud"] if audience else [])
    try:
        return jwt.decode(
            token,
            _oidc_signing_key(token),
            algorithms=algorithms,
            issuer=[issuer, issuer + "/"],
            audience=audience or None,
            options={"require": required, "verify_aud": bool(audience)},
        )
    except (jwt.PyJWTError, requests.RequestException, KeyError, ValueError) as exc:
        # The type for anything that isn't a plain token problem: a library's message can echo a URL.
        log.warning("Rejected identity provider token: %s", exc if isinstance(exc, jwt.PyJWTError) else type(exc).__name__)
        raise HTTPException(status_code=401, detail="Invalid sign-in token")


def email_unverified(claims: dict) -> bool:
    """The provider says this email address has not been proven to belong to the person."""
    return claims.get("email_verified") is False or str(claims.get("email_verified")).lower() == "false"


def email_from_claims(claims: dict) -> str:
    email = claims.get(settings.OIDC_EMAIL_CLAIM)
    if not email or not isinstance(email, str):
        log.warning(
            "Identity provider token has no %r claim - add the email to the provider's token, or set OIDC_EMAIL_CLAIM",
            settings.OIDC_EMAIL_CLAIM,
        )
        raise HTTPException(status_code=401, detail="Sign-in token has no email")
    if email_unverified(claims):
        # Apps identify people by email, so an address nobody proved they own must not sign anyone in.
        raise HTTPException(status_code=401, detail="Your email address hasn't been verified")
    return email


def configured_audience() -> list:
    return [a.strip() for a in (settings.OIDC_AUDIENCE or "").split(",") if a.strip()]


def _email_from_oidc_token(token: str) -> str:
    return email_from_claims(oidc_claims(token, configured_audience()))


def _oidc_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer " and auth[7:].strip():
        return auth[7:].strip()
    cookie = oidc_cookie_name()
    if cookie:
        return request.cookies.get(cookie) or None
    return None


def request_email(request: Request, dev_user_email: str) -> str:
    headers = request.headers
    if settings.ENV == "production":
        cloudflare = bool(settings.CF_TEAM_DOMAIN and settings.CF_ACCESS_AUD)
        if not (cloudflare or oidc_configured()):
            log.error(
                "Neither CF_TEAM_DOMAIN + CF_ACCESS_AUD nor OIDC_ISSUER is set in production - refusing all requests"
            )
            raise HTTPException(status_code=503, detail="Sign-in is not configured on the server")
        # A Cloudflare token, when there is one, is the answer (valid or not: a bad
        # one is never rescued by another credential). Otherwise the provider's.
        cf_token = headers.get(JWT_HEADER) if cloudflare else None
        if cf_token:
            return _email_from_verified_token(cf_token)
        if oidc_configured():
            token = _oidc_token(request)
            if token:
                return _email_from_oidc_token(token)
        raise HTTPException(status_code=401, detail="Not signed in")
    # Local development, signed in through this app's own sign-in flow (a real
    # provider, set up in the developer's shell): that session counts. Never a bare
    # Bearer token, and nothing at all unless the flow is configured.
    if oidc_configured() and (settings.OIDC_CLIENT_ID or settings.OIDC_LOGIN_URL):
        cookie = request.cookies.get(oidc_cookie_name())
        if cookie:
            return _email_from_oidc_token(cookie)
    # Local development: no Cloudflare, so a header or a `dev_user` cookie (set
    # it in the browser console: document.cookie = "dev_user=bob@example.com;
    # path=/") plays a second person; otherwise the configured dev user.
    return headers.get(EMAIL_HEADER) or request.cookies.get("dev_user") or dev_user_email
