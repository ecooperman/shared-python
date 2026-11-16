"""Makes a whole app private to its administrators, for apps that have no accounts of their own.

Those apps were protected only by Cloudflare Access sitting in front of them. To move them to the shared
sign-in (one login, passkeys) the app itself must refuse everyone but the owner, so this wraps the WHOLE app:
every page, every API route and every static file. Middleware rather than a check on each route, so a route
added later cannot be forgotten.

    from shared_python import owner_gate
    owner_gate.install(app, admin_emails=lambda: config.ADMIN_EMAILS, dev_user_email=config.DEV_USER_EMAIL)

For each request:

* A few static files that browsers fetch with no cookies (an installable app's manifest and icons) can be named
  in `public_paths`: GET/HEAD only, an exact path, or a folder when the entry ends in "/". Nothing private belongs there.
* A request that proves itself with a service token the app trusts (`service_access`) is let through, for the
  few calls another app makes on this machine; the app decides which method, path and token.
* Otherwise the person must be signed in (the shared cookie, or Cloudflare Access's token): signed-out visitors
  to a page are sent to the front door and back, everything else is a 401.
* The signed-in email must be one of the administrators, or it is a 403 (a page with a Log out link for browsers).
* With no administrator configured in production nobody gets in (a 503), rather than everybody.
"""
import logging
from typing import Callable, Iterable, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from . import auth, oidc_login, settings

log = logging.getLogger(__name__)


def _wants_a_page(request: Request) -> bool:
    return request.method == "GET" and not request.url.path.startswith("/api/")


def _is_public(request: Request, public_paths: Iterable[str]) -> bool:
    if request.method not in ("GET", "HEAD"):
        return False
    path = request.url.path
    if ".." in path or "//" in path or "\\" in path:  # never let a crafted path wander out of a public folder
        return False
    return any(
        (path.startswith(p) and len(path) > len(p)) if p.endswith("/") else path == p for p in public_paths
    )


def install(
    app,
    admin_emails: Callable[[], Iterable[str]],
    dev_user_email: str,
    service_access: Optional[Callable[[Request], bool]] = None,
    public_paths: Iterable[str] = (),
) -> None:
    """Register the gate on `app`. `admin_emails` is called per request so a changed setting is seen."""
    public_paths = tuple(public_paths)

    @app.middleware("http")
    async def owner_only(request: Request, call_next):
        if _is_public(request, public_paths):
            return await call_next(request)
        if service_access is not None and service_access(request):
            return await call_next(request)
        try:
            email = auth.request_email(request, dev_user_email).strip().lower()
        except HTTPException as exc:
            if exc.status_code == 401:
                if _wants_a_page(request):
                    redirect = oidc_login.redirect_if_signed_out(request, dev_user_email)
                    if redirect is not None:
                        return redirect
                return JSONResponse({"detail": "Not signed in"}, status_code=401, headers={"Cache-Control": "no-store"})
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers={"Cache-Control": "no-store"})
        admins = {a.strip().lower() for a in admin_emails() if a and a.strip()}
        if not admins and settings.ENV == "production":
            log.error("No administrator is configured (ADMIN_EMAILS): refusing every request")
            return JSONResponse({"detail": "No administrator is configured on the server"}, status_code=503)
        if email not in admins:
            if _wants_a_page(request):
                return oidc_login.not_allowed_page(email, request)
            return JSONResponse({"detail": "This app is private"}, status_code=403, headers={"Cache-Control": "no-store"})
        return await call_next(request)
