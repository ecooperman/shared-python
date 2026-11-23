"""Does this email address already have an account at the sign-in provider (Auth0)?

An invite email should carry the link that fits: the sign-in link for someone who already has an account, the create-an-account link for
someone who does not. Sending the wrong one gives the person an unhelpful error, so before an email is drafted the address is looked up.

Only the dashboard (the sign-in front door) holds the provider's management credentials (`AUTH0_MGMT_*`); every other app asks the dashboard
(`POST /internal/account-exists`, on this machine only). The lookup needs the management application to have the `read:users` scope in
Auth0, in addition to the `update:users` it already has for resending verification emails. The answer is only ever used server-side, to choose
the wording of an email an administrator already approved: it is never shown to the person asking or to the invitee's browser.

`exists(email)` is True, False, or None when it cannot tell (nothing configured, the scope missing, the provider or the dashboard not
answering); None always means "send both links", exactly as before, so a failure here can only make an email less tailored, never wrong."""
import logging
from typing import Optional

import requests

from . import oidc_login, settings

log = logging.getLogger(__name__)

PATH = "/internal/account-exists"
TIMEOUT = 5


def _configured() -> bool:
    return bool(settings.AUTH0_MGMT_DOMAIN and settings.AUTH0_MGMT_CLIENT_ID and settings.AUTH0_MGMT_CLIENT_SECRET)


def direct(email: str) -> Optional[bool]:
    """Ask the provider itself (needs the management settings, so only the dashboard can)."""
    if not _configured():
        return None
    try:
        reply = requests.get(
            f"https://{settings.AUTH0_MGMT_DOMAIN}/api/v2/users-by-email",
            params={"email": email.strip().lower()},
            headers={"Authorization": f"Bearer {oidc_login._management_token()}"},
            timeout=TIMEOUT,
        )
        if reply.status_code != 200:
            # 403 is the read:users scope missing: logged so it can be found, and never fatal.
            log.warning("Looking up an account at the sign-in provider answered %s", reply.status_code)
            return None
        found = reply.json()
    except (requests.RequestException, KeyError, ValueError) as exc:
        log.warning("Looking up an account at the sign-in provider failed: %s", type(exc).__name__)
        return None
    return bool(found) if isinstance(found, list) else None


def exists(email: str) -> Optional[bool]:
    """True/False/None as described above, from wherever this process can ask: the provider directly, else the dashboard."""
    if not email or "@" not in email:
        return None
    if _configured():
        return direct(email)
    base = settings.DASHBOARD_API_BASE
    if not base:
        return None
    try:
        reply = requests.post(base.rstrip("/") + PATH, json={"email": email}, timeout=TIMEOUT, allow_redirects=False)
        answer = reply.json().get("exists") if reply.status_code == 200 else None
    except (requests.RequestException, ValueError, AttributeError) as exc:
        log.warning("Asking the dashboard whether an account exists failed: %s", type(exc).__name__)
        return None
    return answer if isinstance(answer, bool) else None
