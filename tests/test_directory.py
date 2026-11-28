"""The cross-app list of people an administrator's 'add a person' box suggests."""
import sqlite3

import pytest

from shared_python import directory


def make_db(base, folder, filename, emails):
    (base / folder).mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(base / folder / filename)
    connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL, status TEXT)")
    connection.executemany("INSERT INTO users (email, status) VALUES (?, 'active')", [(e,) for e in emails])
    connection.commit()
    connection.close()


def test_collects_everyone_from_every_app_without_repeats(tmp_path):
    make_db(tmp_path, "lists", "gifts.db", ["Ann@x.com", "bob@x.com"])
    make_db(tmp_path, "trip-planning", "trips.db", ["bob@x.com", "cy@x.com"])
    make_db(tmp_path, "finances", "finances.db", ["dee@x.com"])
    make_db(tmp_path, "resume", "access.db", ["fay@x.com", "legacy-owner@resume.invalid"])
    assert directory.known_emails(base=tmp_path) == ["ann@x.com", "bob@x.com", "cy@x.com", "dee@x.com", "fay@x.com"]


def test_placeholders_and_junk_are_left_out(tmp_path):
    make_db(tmp_path, "finances", "finances.db", ["legacy-owner@finances.invalid", "real@x.com", "not-an-address"])
    assert directory.known_emails(base=tmp_path) == ["real@x.com"]


def test_extra_addresses_are_included_lowercased(tmp_path):
    make_db(tmp_path, "lists", "gifts.db", ["a@x.com"])
    assert directory.known_emails(extra=["Admin@X.com", ""], base=tmp_path) == ["a@x.com", "admin@x.com"]


def test_a_missing_app_is_skipped_and_nothing_is_created(tmp_path):
    make_db(tmp_path, "lists", "gifts.db", ["a@x.com"])
    assert directory.known_emails(base=tmp_path) == ["a@x.com"]
    assert not (tmp_path / "finances").exists()  # read-only: never makes a database that was not there


def test_an_unreadable_database_does_not_break_the_others(tmp_path, caplog):
    make_db(tmp_path, "lists", "gifts.db", ["a@x.com"])
    (tmp_path / "finances").mkdir()
    (tmp_path / "finances" / "finances.db").write_text("this is not a database")
    assert directory.known_emails(base=tmp_path) == ["a@x.com"]
    assert "Could not read the people in finances" in caplog.text


def test_it_can_only_read(tmp_path):
    make_db(tmp_path, "lists", "gifts.db", ["a@x.com"])
    connection = sqlite3.connect(f"{(tmp_path / 'lists' / 'gifts.db').resolve().as_uri()}?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError):
        connection.execute("INSERT INTO users (email) VALUES ('x@x.com')")


def test_default_folder_is_the_parent_of_the_running_app(monkeypatch, tmp_path):
    monkeypatch.delenv("PEOPLE_APPS_DIR", raising=False)
    (tmp_path / "lists").mkdir()
    monkeypatch.chdir(tmp_path / "lists")
    assert directory.apps_dir() == tmp_path.resolve() or directory.apps_dir() == tmp_path
    monkeypatch.setenv("PEOPLE_APPS_DIR", "/somewhere")
    assert str(directory.apps_dir()) == "/somewhere"


def make_names(base, rows):
    (base / "dashboard").mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(base / "dashboard" / "people.db")
    connection.execute("CREATE TABLE names (email TEXT PRIMARY KEY, first_name TEXT NOT NULL DEFAULT '', last_name TEXT NOT NULL DEFAULT '')")
    connection.executemany("INSERT INTO names VALUES (?, ?, ?)", rows)
    connection.commit()
    connection.close()


def test_people_come_with_their_names_when_the_dashboard_has_them(tmp_path):
    make_db(tmp_path, "lists", "gifts.db", ["ann@x.com", "bob@x.com", "cy@x.com"])
    make_names(tmp_path, [("ann@x.com", "Ann", "Lee"), ("bob@x.com", "Bob", ""), ("someone-else@x.com", "No", "Account")])
    assert directory.known_people(base=tmp_path) == [
        {"email": "ann@x.com", "name": "Ann Lee"}, {"email": "bob@x.com", "name": "Bob"}, {"email": "cy@x.com", "name": ""}]


def test_without_the_names_file_everyone_just_has_no_name(tmp_path):
    make_db(tmp_path, "lists", "gifts.db", ["ann@x.com"])
    assert directory.known_people(base=tmp_path) == [{"email": "ann@x.com", "name": ""}]
    assert not (tmp_path / "dashboard").exists()  # read-only: never created


def test_an_unreadable_names_file_is_skipped_not_fatal(tmp_path, caplog):
    make_db(tmp_path, "lists", "gifts.db", ["ann@x.com"])
    (tmp_path / "dashboard").mkdir()
    (tmp_path / "dashboard" / "people.db").write_text("garbage")
    assert directory.known_people(base=tmp_path) == [{"email": "ann@x.com", "name": ""}]
    assert "Could not read people's names" in caplog.text


def test_a_wal_database_with_no_wal_files_beside_it_is_still_read(tmp_path):
    """An app's database is in WAL mode; its -wal/-shm files vanish when its last connection closes (the app stopped). A plain read-only open
    fails without them, so it falls back to reading the file as it is."""
    make_db(tmp_path, "lists", "gifts.db", ["ann@x.com"])
    database = tmp_path / "lists" / "gifts.db"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("INSERT INTO users (email, status) VALUES ('bob@x.com', 'active')")
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.close()
    for leftover in database.parent.glob("gifts.db-*"):
        leftover.unlink()
    assert directory.known_emails(base=tmp_path) == ["ann@x.com", "bob@x.com"]


def test_a_wal_database_that_an_app_has_open_is_read_including_its_latest_writes(tmp_path):
    make_db(tmp_path, "lists", "gifts.db", ["ann@x.com"])
    writer = sqlite3.connect(tmp_path / "lists" / "gifts.db")
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("INSERT INTO users (email, status) VALUES ('new@x.com', 'active')")
    writer.commit()  # still only in the -wal file, not yet in the .db
    try:
        assert directory.known_emails(base=tmp_path) == ["ann@x.com", "new@x.com"]
    finally:
        writer.close()
