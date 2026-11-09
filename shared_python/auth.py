"""Who is making this request, from Cloudflare Access.

There are no passwords or sign-up forms: every request has already been through
Cloudflare Access, which attaches the signed-in person's email (as a signed
token, Cf-Access-Jwt-Assertion, and as a plain header). This verifies it. Each
app then turns the email into its own user row.

Production verifies the token's signature and audience against Cloudflare's
published keys (needs CF_TEAM_DOMAIN + CF_ACCESS_AUD, see settings.py). Without
them it refuses every request rather than trusting the plain email header: that
header is only set by Access, and a hostname that bypasses Access (or is
misconfigured) lets a visitor send any value they like, which would mean
signing in as anyone.
"""
import logging
from typing import Optional

import jwt
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


def request_email(request: Request, dev_user_email: str) -> str:
    headers = request.headers
    if settings.ENV == "production":
        if not (settings.CF_TEAM_DOMAIN and settings.CF_ACCESS_AUD):
            log.error("CF_TEAM_DOMAIN and CF_ACCESS_AUD must be set in production - refusing all requests")
            raise HTTPException(status_code=503, detail="Sign-in is not configured on the server")
        token = headers.get(JWT_HEADER)
        if not token:
            raise HTTPException(status_code=401, detail="Not signed in")
        return _email_from_verified_token(token)
    # Local development: no Cloudflare, so a header or a `dev_user` cookie (set
    # it in the browser console: document.cookie = "dev_user=bob@example.com;
    # path=/") plays a second person; otherwise the configured dev user.
    return headers.get(EMAIL_HEADER) or request.cookies.get("dev_user") or dev_user_email
