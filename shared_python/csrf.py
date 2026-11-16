"""Refuses a request that CHANGES something unless it really came from the app's own pages.

The sign-in cookie covers the whole parent domain (.evancooperman.com), and every app lives on a subdomain of it,
which browsers treat as the SAME SITE. So SameSite cookies do not help between our own apps: a page on lists could
make a visitor's browser send a POST to finances with their cookie attached, and finances would see a perfectly
valid session. This closes that, and any cross-site version of it, with the headers browsers add themselves and
that a web page cannot forge or remove:

* `Sec-Fetch-Site` (every current browser sends it): for a POST, PUT, PATCH or DELETE it must be `same-origin`.
  `same-site` (another of our apps) and `cross-site` (anywhere else) are refused, as is `none`.
* Where that header is missing (an old browser) but `Origin` is sent, `Origin` must be this app's own origin.
  `Origin: null` (a sandboxed frame, an odd redirect) never matches.
* A request carrying neither header is not from a browser (another app on this machine calling with a service
  token, curl, a test), so it carries no ambient cookie to abuse and is left to the app's own checks.
* `CSRF_TRUSTED_ORIGINS` (comma-separated exact origins, e.g. an installed extension's
  `chrome-extension://<id>`) are allowed explicitly. Nothing is trusted unless it is listed.

Reads (GET, HEAD, OPTIONS) are not touched: they change nothing, and the browser will not show another
origin's response to a page anyway. Cookies are never inspected or logged here.
"""
import logging
from typing import Optional, Set

from fastapi import Request
from fastapi.responses import JSONResponse

from . import settings

log = logging.getLogger(__name__)

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _own_origin(request: Request) -> str:
    """This app's public origin. In production it is always https (Cloudflare terminates TLS and the app sees plain
    http); the host is the one the browser asked for."""
    host = request.headers.get("host") or request.url.netloc
    scheme = "https" if settings.ENV == "production" else request.url.scheme
    return f"{scheme}://{host}".lower()


def _trusted_origins() -> Set[str]:
    return {o.strip().lower() for o in (settings.CSRF_TRUSTED_ORIGINS or "").split(",") if o.strip()}


def refusal(request: Request) -> Optional[str]:
    """Why this request must be refused, or None to let it through."""
    if request.method not in UNSAFE_METHODS:
        return None
    origin = request.headers.get("origin")
    site = request.headers.get("sec-fetch-site")
    if origin is not None and origin.lower() in _trusted_origins():
        return None
    # What was sent goes in the log line (never a cookie), so a legitimate client that is refused can be listed.
    sent = f"Sec-Fetch-Site={(site or '')[:20]!r} Origin={(origin or '')[:80]!r}"
    if site is not None:
        return None if site.lower() == "same-origin" else sent
    if origin is not None:
        return None if origin.lower() == _own_origin(request) else sent
    return None


def install(app) -> None:
    """Register the guard on `app` (a FastAPI/Starlette app)."""

    @app.middleware("http")
    async def refuse_cross_site_changes(request: Request, call_next):
        reason = refusal(request)
        if reason is not None:
            log.warning("Refused a cross-site %s to %s: %s", request.method, request.url.path, reason)
            return JSONResponse(
                {"detail": "That request didn't come from this app, so it was refused"},
                status_code=403, headers={"Cache-Control": "no-store"},
            )
        return await call_next(request)
