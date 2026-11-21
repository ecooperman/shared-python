"""Lets only people who have an account in an app use it, and puts every request inside that person's own data.

For apps whose data is private to each person (finances, plans, time...). It sits around the WHOLE app, like
`owner_gate`, but instead of one administrator list it asks the app who this person is:

    accounts_gate.install(app, account_for=my_lookup, dev_user_email=config.DEV_USER_EMAIL)

`account_for(email)` is the app's own account lookup. It returns an `Account`, or "none" (no account here: default
deny) or "removed" (access was taken away). For each request:

1. A request that proves itself with a service token the app trusts (`service_account`) acts as the account that
   function returns (an administrator's, for the few calls another app makes on this machine); the app decides
   which method, path and token.
2. Otherwise the person must be signed in (shared cookie or Cloudflare Access's token, verified: signature, issuer,
   audience, expiry, and a verified email). Signed-out visitors to a page go to the front door; everything else is 401.
3. The email must have an account, or the request is refused (a page with a Log out link for browsers, a 403 for the API).
4. The rest of the request runs inside `owned.scope(account.id)`: every database read and write on a person's
   data is filtered to them below the app's own code (shared_python.owned), whatever the routes remember to do.

Cross-site changes are refused first (shared_python.csrf). `require_admin` and `current_account` are for routes.
An app may pass `seen=usage.LastSeen(SessionLocal)` to note when each person was last here (shared_python.usage).
"""
import logging
from dataclasses import dataclass
from html import escape
from typing import Callable, Iterable, Optional, Union

from fastapi import HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from . import auth, csrf, oidc_login, owned
from .owner_gate import _is_public  # one definition of what may be public

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Account:
    id: int
    email: str
    is_admin: bool = False


NO_ACCESS = {
    "none": "You haven't been given access to this app. Ask the person who told you about it to invite you.",
    "removed": "Your access to this app has been removed. Ask the administrator if you think that's a mistake.",
}
HEADINGS = {"none": "You don't have access yet", "removed": "Your access was removed"}


def _ask_for_access(problem: str) -> str:
    """For someone who never had an account: a pointer to the dashboard, where they can ask for it. (Someone whose access was
    removed is told to ask the administrator instead; and with no dashboard in front of this app there is nowhere to point.)"""
    url = oidc_login.dashboard_url()
    if problem != "none" or not url:
        return ""
    return (
        '      <p>You can ask for access from your dashboard; an administrator will see your request.</p>\n'
        f'      <p><a class="secondary-btn" href="{escape(url)}" data-btn-icon="unlock">Ask for access</a></p>'
    )


def _wants_a_page(request: Request) -> bool:
    return request.method == "GET" and not request.url.path.startswith("/api/")


def current_account(request: Request) -> Account:
    """For a route: the signed-in person's account (the gate has already checked there is one)."""
    account = getattr(request.state, "account", None)
    if account is None:
        raise HTTPException(status_code=401, detail="Not signed in")
    return account


def require_admin(request: Request) -> Account:
    """For a route that only an administrator may use."""
    account = current_account(request)
    if not account.is_admin:
        raise HTTPException(status_code=403, detail="Only an administrator can do that")
    return account


def install(
    app,
    account_for: Callable[[str], Union[Account, str, None]],
    dev_user_email: str,
    service_account: Optional[Callable[[Request], Optional[Account]]] = None,
    public_paths: Iterable[str] = (),
    seen=None,
) -> None:
    """`seen` is an optional `usage.LastSeen`: a signed-in PERSON (not a service-token call) is recorded as last seen, at most once an hour."""
    public_paths = tuple(public_paths)

    @app.middleware("http")
    async def accounts_only(request: Request, call_next):
        if _is_public(request, public_paths):
            return await call_next(request)
        account: Optional[Account] = None
        if service_account is not None:
            account = service_account(request)
        person_request = account is None
        if account is None:
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
            found = await run_in_threadpool(account_for, email)
            if not isinstance(found, Account):
                problem = found if found in NO_ACCESS else "none"
                if _wants_a_page(request):
                    return oidc_login._page(
                        HEADINGS[problem], f"{NO_ACCESS[problem]} You're signed in as {email}; if that's the wrong address, sign out and sign in again.",
                        403, retry_label="Sign out", href=oidc_login.logout_url(request) or "/cdn-cgi/access/logout",
                        extra_html=_ask_for_access(problem),
                    )
                return JSONResponse({"detail": NO_ACCESS[problem]}, status_code=403, headers={"Cache-Control": "no-store"})
            account = found
        request.state.account = account
        if seen is not None and person_request and seen.due(account.id):
            await run_in_threadpool(seen.record, account.id)  # a quick write, once an hour per person; never raises
        with owned.scope(account.id):
            return await call_next(request)

    csrf.install(app)  # registered last, so it runs first
    auth.warm_up_on_start(app)  # the sign-in keys are fetched in the background at start-up, not by the first visitor
