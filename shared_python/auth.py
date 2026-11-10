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
from typing import Optional

import jwt
import requests
from fastapi import HTTPException, Request

from . import settings

log = logging.getLogger(__name__)

EMAIL_HEADER = "cf-access-authenticated-user-email"
JWT_HEADER = "cf-access-jwt-assertion"

_jwks_client: Optional[jwt.PyJWKClient] = None


def _signing_key(token: str):
    """Cloudflare's public key for this token (cached by PyJWKClient)."""
    global _jwks_client
    if _jwks_client is None:
        # Forgive a pasted "https://" or trailing slash - it's just a hostname.
        domain = settings.CF_TEAM_DOMAIN.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        _jwks_client = jwt.PyJWKClient(f"https://{domain}/cdn-cgi/access/certs", lifespan=3600)
    return _jwks_client.get_signing_key_from_jwt(token).key


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

_oidc_client: Optional[jwt.PyJWKClient] = None
_oidc_client_key: Optional[str] = None

# Only asymmetric algorithms are ever accepted: allowing HS256 would let anyone who
# knows the (public) key sign tokens with it.
_ASYMMETRIC = ("RS", "ES", "PS", "EdDSA")


def oidc_configured() -> bool:
    return bool(settings.OIDC_ISSUER)


def _oidc_algorithms() -> list:
    wanted = [a.strip() for a in settings.OIDC_ALGORITHMS.split(",") if a.strip()]
    return [a for a in wanted if a.startswith(_ASYMMETRIC)]


def _oidc_jwks_url() -> str:
    """Where the provider publishes its signing keys: given explicitly, or found
    through the issuer's standard discovery document."""
    if settings.OIDC_JWKS_URL:
        return settings.OIDC_JWKS_URL
    issuer = settings.OIDC_ISSUER.rstrip("/")
    resp = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    resp.raise_for_status()
    return resp.json()["jwks_uri"]


def _oidc_signing_key(token: str):
    """The provider's public key for this token (keys cached by PyJWKClient)."""
    global _oidc_client, _oidc_client_key
    if _oidc_client is None or _oidc_client_key != (settings.OIDC_JWKS_URL, settings.OIDC_ISSUER):
        _oidc_client = jwt.PyJWKClient(_oidc_jwks_url(), lifespan=3600)
        _oidc_client_key = (settings.OIDC_JWKS_URL, settings.OIDC_ISSUER)
    return _oidc_client.get_signing_key_from_jwt(token).key


def _email_from_oidc_token(token: str) -> str:
    algorithms = _oidc_algorithms()
    if not algorithms:
        log.error("OIDC_ALGORITHMS has no asymmetric algorithm - refusing provider tokens")
        raise HTTPException(status_code=503, detail="Sign-in is not configured on the server")
    issuer = settings.OIDC_ISSUER.rstrip("/")
    audience = [a.strip() for a in (settings.OIDC_AUDIENCE or "").split(",") if a.strip()]
    required = ["exp", "iss"] + (["aud"] if audience else [])
    try:
        claims = jwt.decode(
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
    email = claims.get(settings.OIDC_EMAIL_CLAIM)
    if not email or not isinstance(email, str):
        log.warning(
            "Identity provider token has no %r claim - add the email to the provider's token, or set OIDC_EMAIL_CLAIM",
            settings.OIDC_EMAIL_CLAIM,
        )
        raise HTTPException(status_code=401, detail="Sign-in token has no email")
    if claims.get("email_verified") is False or str(claims.get("email_verified")).lower() == "false":
        # Apps identify people by email, so an address nobody proved they own must not sign anyone in.
        raise HTTPException(status_code=401, detail="Your email address hasn't been verified")
    return email


def _oidc_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer " and auth[7:].strip():
        return auth[7:].strip()
    if settings.OIDC_COOKIE:
        return request.cookies.get(settings.OIDC_COOKIE) or None
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
    # Local development: no Cloudflare, so a header or a `dev_user` cookie (set
    # it in the browser console: document.cookie = "dev_user=bob@example.com;
    # path=/") plays a second person; otherwise the configured dev user.
    return headers.get(EMAIL_HEADER) or request.cookies.get("dev_user") or dev_user_email
