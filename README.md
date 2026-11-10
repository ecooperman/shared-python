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
| `shared_python.cloudflare` | Whether an email is let through the Access gate (`is_let_in`) and adding one to the Invitees group (`allow_email`). |
| `shared_python.notify` | Telling the administrator something needs them (ntfy / Pushover / email), and emailing a person they've been given access (`tell_given_access`) or let into the app (`tell_let_in`). |
| `shared_python.keystore` | Encrypting a person's own API key for storage (Fernet, keyed from `KEY_ENCRYPTION_SECRET`): `encrypt`, `decrypt`, `clean`, `last4`, `scrub`. Which providers exist, how a key is checked and the table it lives in stay with each app (see trip-planning's `app/apikeys.py`). |

What differs between apps is passed in by the app, never read from here: the
administrators (`is_let_in(email, admin_emails)`), the app's name, and the links in
emails. Each app keeps a thin `app/notify.py` and `app/auth.py` with its own wording
and its own user table, and calls into this.

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
