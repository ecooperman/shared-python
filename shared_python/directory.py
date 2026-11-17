"""Who has an account in any of the apps: the suggestions for an administrator's "add a person" box.

Each app keeps its own users table in its own database, so "everyone already invited somewhere" means reading the
others'. The apps all live side by side on one machine (/opt/apps/<repo> on the droplet, ~/code/personal-projects
locally), so this opens each sibling's database READ-ONLY and takes the `email` column of its `users` table - nothing
else is ever read, and nothing needs a token or a network call between apps.

    from shared_python import directory
    directory.known_emails()        # sorted, lowercased, every address in any app

This is for ADMINISTRATOR-only endpoints. Never hand the result to an ordinary person: it says who else uses the apps.
The caller removes whoever already has access in its own app (it knows that better than this does).
"""
import logging
import os
import sqlite3
from pathlib import Path
from typing import Iterable, List, Optional

log = logging.getLogger(__name__)

# repo folder -> database file in it (the apps' default DATABASE_URL; each has a `users` table with an `email` column).
APP_DATABASES = {
    "lists": "gifts.db",
    "trip-planning": "trips.db",
    "social-planning": "ideas.db",
    "time-management": "tasks.db",
    "finances": "finances.db",
    "resume": "access.db",
}

# The dashboard keeps people's first and last names in its own file (dashboard/app/people.py); read here the same way.
NAMES_DATABASE = ("dashboard", "people.db")

# Placeholder owners parked on pre-account data until an administrator signs in (never a real person).
_PLACEHOLDER_SUFFIX = ".invalid"


def apps_dir() -> Path:
    """The folder that holds the app repos: PEOPLE_APPS_DIR if set, otherwise the parent of the running app's own folder."""
    configured = os.environ.get("PEOPLE_APPS_DIR")
    return Path(configured) if configured else Path.cwd().parent


def _emails_in(database: Path) -> List[str]:
    # mode=ro: this can never write, and never creates a missing file (SQLite would otherwise make an empty one).
    connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=2)
    try:
        return [row[0] for row in connection.execute("SELECT email FROM users")]
    finally:
        connection.close()


def _names_in(database: Path) -> dict:
    connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=2)
    try:
        rows = connection.execute("SELECT email, first_name, last_name FROM names")
        return {e.strip().lower(): " ".join(part for part in (f, l) if part) for e, f, l in rows}
    finally:
        connection.close()


def known_people(extra: Optional[Iterable[str]] = None, base: Optional[Path] = None) -> List[dict]:
    """Like known_emails, but each person as {"email", "name"} (name is "" when nobody has given one), sorted by email.
    Names come from the dashboard's own file, read-only; without it everyone just has no name."""
    base = base or apps_dir()
    names = {}
    path = base / NAMES_DATABASE[0] / NAMES_DATABASE[1]
    if path.is_file():
        try:
            names = _names_in(path)
        except sqlite3.Error as exc:
            log.warning("Could not read people's names: %s", exc)
    return [{"email": e, "name": names.get(e, "")} for e in known_emails(extra=extra, base=base)]


def known_emails(extra: Optional[Iterable[str]] = None, base: Optional[Path] = None) -> List[str]:
    """Every address with an account (or a removed one) in any app, lowercased and sorted. `extra` is added as-is
    (an app's own administrators, who may not have a row yet). A database that is missing or unreadable is skipped."""
    base = base or apps_dir()
    found = {e.strip().lower() for e in (extra or []) if e and e.strip()}
    for folder, filename in APP_DATABASES.items():
        path = base / folder / filename
        if not path.is_file():
            continue
        try:
            found.update(e.strip().lower() for e in _emails_in(path) if e)
        except sqlite3.Error as exc:
            log.warning("Could not read the people in %s: %s", folder, exc)
    return sorted(e for e in found if "@" in e and not e.endswith(_PLACEHOLDER_SUFFIX))
