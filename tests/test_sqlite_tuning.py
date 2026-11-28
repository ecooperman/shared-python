"""The shared SQLite settings: WAL, a busy timeout and a lighter sync, on every new connection of an app's engine."""
import logging

from sqlalchemy import create_engine, text

from shared_python import sqlite_tuning


def pragma(engine, name):
    with engine.connect() as connection:
        return connection.execute(text(f"PRAGMA {name}")).scalar()


def test_every_connection_of_a_file_database_gets_wal_a_timeout_and_normal_sync(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'app.db'}", connect_args={"check_same_thread": False})
    sqlite_tuning.tune(engine)
    assert pragma(engine, "journal_mode") == "wal"
    assert pragma(engine, "busy_timeout") == 5000
    assert pragma(engine, "synchronous") == 1  # NORMAL


def test_the_mode_is_kept_in_the_file_so_it_stays_on_without_tuning(tmp_path):
    path = tmp_path / "app.db"
    tuned = create_engine(f"sqlite:///{path}")
    sqlite_tuning.tune(tuned)
    pragma(tuned, "journal_mode")
    tuned.dispose()
    assert pragma(create_engine(f"sqlite:///{path}"), "journal_mode") == "wal"


def test_a_reader_is_not_held_up_by_an_open_write(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'app.db'}", connect_args={"check_same_thread": False})
    sqlite_tuning.tune(engine)
    with engine.begin() as setup:
        setup.execute(text("CREATE TABLE t (n INTEGER)"))
        setup.execute(text("INSERT INTO t VALUES (1)"))
    writer = engine.connect()
    writer.execute(text("INSERT INTO t VALUES (2)"))  # a write transaction left open
    try:
        with engine.connect() as reader:
            assert reader.execute(text("SELECT count(*) FROM t")).scalar() == 1  # sees the committed row at once, no waiting, no "locked"
    finally:
        writer.rollback()
        writer.close()


def test_an_in_memory_database_carries_on(tmp_path):
    engine = create_engine("sqlite://")
    sqlite_tuning.tune(engine)
    assert pragma(engine, "journal_mode") == "memory"


def test_a_setting_that_cannot_be_applied_is_logged_not_raised(caplog):
    class Broken:
        def cursor(self):
            return self

        def execute(self, sql):
            raise RuntimeError("no")

        def close(self):
            pass

    with caplog.at_level(logging.WARNING):
        sqlite_tuning.configure(Broken())
    assert caplog.text.count("Could not set SQLite") == 3
