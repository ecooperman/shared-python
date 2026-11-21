"""A rough picture of whether and how an app is being used, for the dashboard's stats pages. Two small pieces, both counts and dates only
(never anyone's titles, text or amounts):

* `LastSeen`: when each person last used the app and on how many different days. Every app's `users` table has two columns for it,
  `last_seen_at` (UTC) and `active_days`. Writing on every request would be wasteful, so a person is recorded at most once an hour per
  process (the check is an in-memory dictionary, so it costs nothing on the other requests), and a failure to record is logged and
  ignored: counting must never break a request.

* `build`: the answer to the app's administrator-only `GET /api/admin/stats`. For each account: status, when it was made, last seen,
  active days, and per-person counts of whatever the app chooses to count (`per_user` makes one such count from any table that
  says whose a row is), each with the date of the newest row. The dashboard puts the apps' answers together.

Both are plain SQLAlchemy; an app passes in its own session factory and models."""
import logging
import threading
import time
from datetime import datetime
from typing import Callable, Dict, Optional, Tuple

import requests

from sqlalchemy import DateTime, Integer, String, case, column, func, or_, select, table, update

from . import settings

log = logging.getLogger(__name__)

RECORD_EVERY_SECONDS = 3600

# A lightweight handle on the columns every app's users table has: not an app model, so no app's ownership filter touches it.
_users = table("users", column("id", Integer), column("email", String), column("last_seen_at", DateTime), column("active_days", Integer))


class LastSeen:
    """`LastSeen(SessionLocal)`; then `if seen.due(user_id): seen.record(user_id)` (in a worker thread, if the caller is async)."""

    def __init__(self, session_factory: Callable, every_seconds: int = RECORD_EVERY_SECONDS, clock: Callable[[], float] = time.time, app: Optional[str] = None):
        self._app = app  # the app's key on the dashboard ("lists"); given, the dashboard is told about each person's first visit of a day
        self._session_factory = session_factory
        self._every = every_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._last: Dict[int, float] = {}

    def reset(self) -> None:
        """Forget who was recorded when. For tests, which empty the database between them but keep the process."""
        with self._lock:
            self._last.clear()

    def due(self, user_id: int) -> bool:
        with self._lock:
            return self._clock() - self._last.get(user_id, float("-inf")) >= self._every

    def record(self, user_id: int, now: Optional[datetime] = None) -> None:
        """Note that this person is here now: last seen is now, and the number of active days goes up by one if they were last seen on an
        earlier (UTC) day or never. Never raises."""
        with self._lock:
            self._last[user_id] = self._clock()  # even if the write fails, so a broken table is tried once an hour, not on every request
        now = now or datetime.utcnow()
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        days = func.coalesce(_users.c.active_days, 0)
        statement = (
            update(_users)
            .where(_users.c.id == user_id)
            .values(active_days=case((or_(_users.c.last_seen_at.is_(None), _users.c.last_seen_at < today), days + 1), else_=days), last_seen_at=now)
        )
        new_day, email = False, None
        try:
            with self._session_factory() as session:
                before = session.execute(select(_users.c.last_seen_at).where(_users.c.id == user_id)).first()
                new_day = before is not None and (before[0] is None or before[0] < today)  # their first visit of this (UTC) day
                session.execute(statement)
                session.commit()
                if new_day and self._app:
                    email = session.execute(select(_users.c.email).where(_users.c.id == user_id)).scalar()
        except Exception as exc:  # noqa: BLE001 - counting must never break the request that triggered it
            log.warning("Could not record when someone was last seen: %s", type(exc).__name__)
        if email:
            _announce(self._app, email, today)


ACTIVE_DAY_PATH = "/internal/active-day"


def _send_active_day(app: str, email: str, day: str) -> None:
    base = settings.DASHBOARD_API_BASE
    if not base:
        return
    try:
        requests.post(base.rstrip("/") + ACTIVE_DAY_PATH, json={"app": app, "email": email, "day": day}, timeout=2)
    except Exception as exc:  # noqa: BLE001 - the dashboard being away must never matter here
        log.warning("Could not tell the dashboard about a day of use: %s", type(exc).__name__)


def _announce(app: str, email: str, today: datetime) -> None:
    """Tell the dashboard, in the background, that this person used `app` today (once per person per UTC day: that is the only time this is
    called). The dashboard adds one to that day's count for the app and keeps no address (dashboard/app/trend.py). Nothing is sent when
    settings.DASHBOARD_API_BASE is empty (locally and in tests)."""
    if not settings.DASHBOARD_API_BASE:
        return
    threading.Thread(target=_send_active_day, args=(app, email, today.date().isoformat()), daemon=True).start()


def per_user(db, owner_column, newest_column=None, where=None, source=None) -> Dict[int, Tuple[int, Optional[datetime]]]:
    """How many rows each person has, and the newest one's date: {user_id: (count, newest or None)}. `owner_column` is whatever column
    holds the person's id (an owned table's `owner_id`, a membership's `user_id`). For an owned table run this inside
    `owned.unscoped()` so every person's rows are counted, not only the signed-in administrator's. `where` narrows what is counted
    (`Job.tier.isnot(None)`: only the scored ones). `source` is a join when the rows to count do not carry the person themselves (items
    belong to a list, and the list to a person: `ItemList.__table__.join(Item.__table__, Item.list_id == ItemList.id)`)."""
    columns = [owner_column, func.count()]
    if newest_column is not None:
        columns.append(func.max(newest_column))
    query = select(*columns).group_by(owner_column)
    if source is not None:
        query = query.select_from(source)
    if where is not None:
        query = query.where(where)
    out: Dict[int, Tuple[int, Optional[datetime]]] = {}
    for row in db.execute(query).all():
        out[row[0]] = (row[1], row[2] if newest_column is not None else None)
    return out


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.replace(microsecond=0).isoformat() + "Z" if value is not None else None


def build(db, user_model, measures: Dict[str, Dict[int, Tuple[int, Optional[datetime]]]]) -> dict:
    """The body of an app's `GET /api/admin/stats`: {"accounts": [...]}, one entry per account, oldest first. `measures` maps a label
    ("lists", "items") to a `per_user` result. `last_activity_at` is the latest of last seen and the newest row of any measure, which
    also covers anything that happened before last-seen tracking began."""
    accounts = []
    for user in db.query(user_model).order_by(user_model.id).all():
        counts, newest = {}, []
        for label, found in measures.items():
            count, when = found.get(user.id, (0, None))
            counts[label] = count
            if when is not None:
                newest.append(when)
        last_seen = getattr(user, "last_seen_at", None)
        latest = max(newest + ([last_seen] if last_seen else []), default=None)
        accounts.append({
            "email": user.email,
            "status": user.status,
            "created_at": _iso(getattr(user, "created_at", None)),
            "last_seen_at": _iso(last_seen),
            "active_days": getattr(user, "active_days", None) or 0,
            "counts": counts,
            "last_activity_at": _iso(latest),
        })
    return {"accounts": accounts}
