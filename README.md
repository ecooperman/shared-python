# shared-python

Code the personal apps share instead of each keeping its own copy: signing in through
Cloudflare Access, letting someone through the Access gate, telling people things, and encrypting
people's own API keys.
It sits next to the apps (`~/code/personal-projects/shared-python`, and
`/opt/apps/shared-python` on the droplet) the way `shared-assets` does for the
front-end files.

| Module | What it does |
|---|---|
| `shared_python.settings` | The settings every app reads from the shared environment file (`/etc/personal-apps/shared.env`): Cloudflare, ntfy, Pushover, SMTP, and `KEY_ENCRYPTION_SECRET`. |
| `shared_python.auth` | `request_email(request, dev_user_email)`: who is signed in, from Cloudflare Access's signed token (refuses everything in production if that isn't configured; a header or cookie plays other people locally). |
| `shared_python.oidc_login` | The app's own sign-in through a hosted identity provider: `/auth/login`, `/auth/callback`, `/auth/logout` (a router to mount) and `redirect_if_signed_out(request)` for HTML pages. Authorization-code flow with PKCE, state and nonce; plain OIDC, no vendor SDK. |
| `shared_python.owned` | Per-person data ownership for SQLAlchemy apps: models inherit `OwnedMixin` (an `owner_id`), and while a request runs inside `scope(person_id)` EVERY select, update and delete on those tables is filtered to that person below the app's own code (joins, aggregates, relationship loads and by-id lookups included); with no scope nothing matches (fail closed); new rows get their owner from the scope; a write that would put a row in someone else's name, move it, or change or delete someone else's row raises. `unscoped()` is the explicit way out, for migrations and account lookups only. Known limits: raw SQL, a bare `exists().where(...)` and `from_statement`, which `assert_no_raw_sql` lets a test forbid. |
| `shared_python.accounts_gate` | `install(app, account_for=..., dev_user_email=...)`: like `owner_gate` but for apps where each person has an account and private data. The app's `account_for(email)` returns an `Account` (id, email, is_admin), or "none" (default-deny) or "removed"; the rest of the request runs inside `owned.scope(account.id)`. `service_account` lets one narrow machine-to-machine call act as an account; `current_account` and `require_admin` are for routes. Includes the cross-site guard. |
| `shared_python.usage` | A rough picture of whether an app is used, for the dashboard's Usage pages (counts and dates only). `LastSeen(SessionLocal)` records, at most once an hour per person, when each person was last in the app and on how many different days (columns `last_seen_at` and `active_days` on the app's `users` table); `accounts_gate.install(..., seen=...)` calls it for people (not service-token calls), and an app with its own sign-in calls it from its `current_user`. `per_user` counts any table by the person it belongs to (optionally the newest date, a `where`, or a join), `build` makes the body of the app's administrator-only `GET /api/admin/stats`. Run the counts of an owned table inside `owned.unscoped()`. `LastSeen(SessionLocal, app="lists")` also tells the dashboard (POST `/internal/active-day`, in the background, only in production unless `DASHBOARD_API_BASE` is set) the first time it sees a person on a new UTC day, for the Usage page's daily chart. |
| `shared_python.probe` | `PROBE_HEADER` (`X-Brassworks-Probe`) and `is_probe(request)`: the dashboard marks its own "does this person have an account here?" and admin calls with it, so an app never counts them as the person being there (`usage`, `accounts_gate`, lists' and trips' `current_user` skip last-seen for a probe). No dependencies (the dashboard imports it too). |
| `shared_python.access_events` | `install(models.User)`, once per app: when a user row is added or its `status` changes, the dashboard is told (after the commit, in a background thread, failures only logged) so it forgets that person's remembered list of apps (`POST /internal/access-changed`, `settings.DASHBOARD_API_BASE`, on only in production unless set). |
| `shared_python.feedback_relay` | `install(app, "lists", dependencies=[Depends(current_user)])`: the app's own `POST /api/feedback`, behind its own sign-in, which passes a Send feedback message to the dashboard's one inbox (`POST /internal/feedback` on `settings.DASHBOARD_API_BASE`) with the app's key (never the sender's choice) and only the person's sign-in cookie. Apps behind `accounts_gate` need no dependency. |
| `shared_python.netguard` | Safe fetching of addresses people type in: public addresses only (never this machine's own network), every redirect hop checked, body capped. Use it for ANY server-side fetch of a user-supplied URL. |
| `shared_python.csrf` | `install(app)`: refuses any POST, PUT, PATCH or DELETE the browser does not mark as coming from the app's own origin (`Sec-Fetch-Site: same-origin`; `Origin` as the fallback for old browsers). Needed because the sign-in cookie covers every subdomain and subdomains are the same site, so one app's page could otherwise change data in another. `CSRF_TRUSTED_ORIGINS` lists exact origins allowed anyway (an installed extension). Requests with no browser headers (another app calling with a service token) are left to the app's own checks. Every private app gets it through `owner_gate`; lists, trips and the dashboard install it themselves. |
| `shared_python.owner_gate` | `install(app, admin_emails=..., dev_user_email=...)`: makes a WHOLE app private to its administrators, for apps with no accounts (every page, API route and static file; signed-out visitors go to the front door, anyone else is refused; no administrator configured = nobody in). `service_access` lets one narrow machine-to-machine call through; `public_paths` names the few files browsers fetch with no cookie (manifest, icons). |
| `shared_python.cloudflare` | Whether an email is let through the Access gate (`is_let_in`) and adding one to the Invitees group (`allow_email`). |
| `shared_python.notify` | Telling the administrator something needs them (ntfy / Pushover / email), and emailing a person they've been given access (`tell_given_access`) or let into the app (`tell_let_in`). |
| `shared_python.keystore` | Encrypting a person's own API key for storage (Fernet, keyed from `KEY_ENCRYPTION_SECRET`): `encrypt`, `decrypt`, `clean`, `last4`, `scrub`. Which providers exist, how a key is checked and the table it lives in stay with each app (see trip-planning's `app/apikeys.py`). |

What differs between apps is passed in by the app, never read from here: the
administrators (`is_let_in(email, admin_emails)`), the app's name, and the links in
emails. Each app keeps a thin `app/notify.py` and `app/auth.py` with its own wording
and its own user table, and calls into this.

`directory.known_emails()` is the one place an app learns about people in the OTHER apps: it opens each sibling
app's database read-only (they sit side by side, `/opt/apps/<repo>` on the droplet) and returns the addresses in their
`users` tables, for an administrator's "add a person" autocomplete. No tokens, no network, nothing written. Never show
the result to an ordinary person: it says who else uses the apps. `PEOPLE_APPS_DIR` overrides where it looks.

## Using it in an app

```
# requirements.txt
-e ../shared-python
```

`pip install -r requirements.txt` is always run from the app's own folder (locally and
by the deploy workflow), so that relative path is the sibling folder in both places.
Locally, install it into the app's venv once: `venv/bin/pip install -e ../shared-python`.

```python
from shared_python import auth, cloudflare, keystore, notify
```

## Signing in with a hosted identity provider

`shared_python.auth` accepts a verified Cloudflare Access token, a verified token from
any OIDC identity provider, or both (so an app can move across without a flag day). Nothing
changes until `OIDC_ISSUER` is set in `/etc/personal-apps/shared.env`. Which provider it is
is only settings:

| Setting | What to put |
|---|---|
| `OIDC_ISSUER` | The token's `iss` value (a trailing slash either way is fine). Keys are found at `{issuer}/.well-known/openid-configuration`. |
| `OIDC_JWKS_URL` | Only if the provider has no discovery document: where its signing keys are. |
| `OIDC_AUDIENCE` | The token's `aud` (comma-separated for several). Leave unset only if the provider's tokens carry none. |
| `OIDC_ALGORITHMS` | Default `RS256,ES256`. Only asymmetric algorithms are ever used, whatever is set. |
| `OIDC_EMAIL_CLAIM` | Default `email`. Some providers leave the email out of their tokens unless you add it (a custom claim or token template) - the log says which claim was missing. |
| `OIDC_COOKIE` | The provider's session cookie name, if it delivers the token that way. An `Authorization: Bearer` token always works. |

A token whose `email_verified` is false is refused: apps identify people by email, so an
address nobody proved they own must not sign anyone in. Production still refuses every
request when neither Cloudflare nor a provider is configured.

### The app doing the sign-in itself (`oidc_login`)

Instead of waiting for a token to arrive, the app sends people to the provider and receives
them back. Mount it once (`app.include_router(oidc_login.router)`), and in each HTML page's route
start with `oidc_login.redirect_if_signed_out(request, DEV_USER_EMAIL)` (return it if it isn't None).
APIs keep answering 401. Nothing is reachable (404) until these are set, and none of it
is used locally unless they are:

| Setting | What to put |
|---|---|
| `OIDC_CLIENT_ID` | The provider application's client id. Also put it in `OIDC_AUDIENCE`: it is the ID token's audience. |
| `OIDC_CLIENT_SECRET` | The application's secret, if its type has one (sent with PKCE). Leave unset for a public client. |
| `OIDC_SCOPES` | Default `openid email profile`. |
| `OIDC_ISSUER` | May list several, comma-separated, to run two providers side by side while moving: a token from any of them is accepted, and **the first one is where people are sent to sign in**. `OIDC_JWKS_URL` applies only with a single issuer. |

Register `https://<app host>/auth/callback` as an allowed callback and `https://<app host>/` as
an allowed logout URL at the provider (and the `http://localhost:<port>` pair for local runs).
The ID token is kept in an httponly, host-only cookie (`oidc_session`, or `OIDC_COOKIE`) for as long as
the token lives; when it ends, the next page visit goes back through the provider, which signs the
person straight in again while their provider session lasts. Locally, only a session made by this flow
counts (a bare bearer token never does); with no session the configured dev user is still used.
The Log out link follows `logout_url` in the app's `/api/me` (see lists' `app/routers/me.py`).

### One front door for every app

Rather than every app signing people in itself, one app (the **dashboard**, `dashboard.evancooperman.com`)
does it and sets the session cookie for the whole parent domain; every other app only checks the cookie.

| Setting | Where | What to put |
|---|---|---|
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | **the dashboard's own env file only** | The Auth0 application. The secret must not be in `shared.env`, which every app reads. |
| `OIDC_COOKIE_DOMAIN` | the dashboard | `.evancooperman.com`: the cookie then reaches every subdomain, so one sign-in (and one log out) covers all apps. Unset = host-only. |
| `OIDC_RETURN_HOSTS` | the dashboard | Where it may send people back to: `.evancooperman.com` (any subdomain, not the bare domain) or exact hosts. Locally `localhost`/`127.0.0.1` are allowed when unset; in production nothing is unless set. |
| `OIDC_ISSUER`, `OIDC_AUDIENCE` | `shared.env` | Same as above (the audience is the client id). |
| `OIDC_LOGIN_URL` | `shared.env` (every other app) | `https://dashboard.evancooperman.com/auth/login`. With it set, an app does no sign-in of its own: `redirect_if_signed_out` sends a signed-out visitor to the dashboard carrying the **full address** they wanted, and `logout_url(request)` is the dashboard's `/auth/logout` (ends the session for every app). |

The return address is the sensitive part: `safe_next` accepts a path on the same site, or a full `https`
address (plain `http` only locally) whose host is on `OIDC_RETURN_HOSTS`, and turns everything else
(other hosts, look-alike suffixes, `user@host` tricks, `//host`, control characters, non-ASCII hosts,
over-long values) into `/`. It is checked when the sign-in starts **and again** when the person comes back,
because the pending-login cookie is the browser's to edit.

**Checklist when trying a provider:** the issuer and audience it puts in tokens; whether the
email is in the token (and under what name); whether it verifies emails; where the token
travels (cookie name or bearer); that its cookie is shared across `*.evancooperman.com` if
the apps are on different subdomains.

## Changing it

Several apps run this code, so a change reaches all of them. Keep signatures stable
(add parameters with defaults), run **every dependent app's tests** before pushing,
and remember each app must restart to pick a change up - the deploy workflow in this
repo does that for the apps listed in `.github/workflows/deploy.yml` (add a line when
another app starts using the package).

```bash
python3 -m venv venv && venv/bin/pip install -r requirements-dev.txt
venv/bin/pytest
```

The tests blank every setting and fail any real network or SMTP call, so they can't
touch Cloudflare, ntfy or your mail.

## On the droplet (one time)

```bash
sudo -iu deploy
cd /opt/apps
git clone https://github.com/ecooperman/shared-python.git
```

Clone it as `deploy`, not root. If git later says "detected dubious ownership", the folder
isn't owned by `deploy`: run `sudo chown -R deploy:deploy /opt/apps/shared-python` (don't
use `safe.directory`; the apps' `pip install -e` needs to write there too).

This repo's deploy restarts the apps, so each app's venv must already have the package
installed (run `pip install -r requirements.txt` in the app, as `deploy`) before this
workflow first runs, or the apps crash-loop with `No module named 'shared_python'`.

Do this **before** pushing an app that lists `-e ../shared-python` in its
requirements, or that app's deploy fails at `pip install`. The repo also needs the same
three GitHub Actions secrets as the apps (`DO_HOST`, `DO_USER`, `DO_SSH_KEY`) so its
own deploy workflow can restart the apps.
