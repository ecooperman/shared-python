"""The SQLite settings every app's database connection should have, set in ONE place.

    # app/database.py, right after create_engine(...)
    from shared_python import sqlite_tuning
    sqlite_tuning.tune(engine)

Each new connection then runs three PRAGMAs:

* `busy_timeout=5000` - a request that finds the file briefly locked waits up to 5 seconds instead of failing with "database is locked".
  (Python's sqlite3 already waits 5 s by default; this makes it explicit and the same everywhere.)
* `journal_mode=WAL` - write-ahead logging: a reader no longer waits for a writer (and the reverse). Every page load that also writes
  (a last-seen stamp, a rollover) used to hold readers up. The mode is stored in the database file, so it sticks after the first start; the
  `-wal` and `-shm` files beside the .db are normal while an app runs.
* `synchronous=NORMAL` - with WAL, a commit no longer waits for the disk to confirm every write. The trade-off: a power cut or hard
  crash of the machine can lose the last moments of committed writes, but never corrupts the database. An app crash loses nothing.

WAL CHANGES TWO THINGS TO KNOW (also in DEPLOYMENT.md):
* RESTORING a backup: stop the app, delete the live `<db>-wal` and `<db>-shm` files, then copy the backup over the .db. A stale -wal beside
  a restored .db would be replayed into it. `backup-dbs.sh` stops the app first, so its copy is clean.
* READING another app's file (`shared_python.directory`) needs the -wal/-shm files, or `immutable=1`; directory.py falls back to that.

An in-memory database (tests) answers `memory` to the WAL request and carries on; a failure to set a pragma is logged, never raised, so an
app always starts."""
import logging

log = logging.getLogger(__name__)

BUSY_TIMEOUT_MS = 5000
# Order matters: the timeout first, so switching to WAL (which needs a brief exclusive lock) waits instead of failing.
PRAGMAS = (("busy_timeout", BUSY_TIMEOUT_MS), ("journal_mode", "WAL"), ("synchronous", "NORMAL"))


def configure(dbapi_connection) -> None:
    """Apply the settings to one raw sqlite3 connection."""
    cursor = dbapi_connection.cursor()
    try:
        for name, value in PRAGMAS:
            try:
                cursor.execute(f"PRAGMA {name}={value}")
            except Exception as exc:  # noqa: BLE001 - never stop an app starting over a tuning setting
                log.warning("Could not set SQLite %s: %s", name, exc)
    finally:
        cursor.close()


def tune(engine) -> None:
    """Make every connection of a SQLAlchemy engine use the settings. Does nothing for a database that is not SQLite."""
    from sqlalchemy import event

    if engine.dialect.name != "sqlite":
        return
    event.listen(engine, "connect", lambda dbapi_connection, _record: configure(dbapi_connection))
