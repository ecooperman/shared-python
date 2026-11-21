"""Last-seen tracking and the per-person counts behind the dashboard's stats pages."""
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from shared_python import accounts_gate, owned, usage
from shared_python.accounts_gate import Account

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    status = Column(String, nullable=False, default="active")
    created_at = Column(DateTime, default=datetime(2026, 1, 1))
    last_seen_at = Column(DateTime, nullable=True)
    active_days = Column(Integer, nullable=False, default=0, server_default="0")


class Thing(Base, owned.OwnedMixin):
    __tablename__ = "things"
    id = Column(Integer, primary_key=True)
    made = Column(DateTime, nullable=False)


class Part(Base):
    __tablename__ = "parts"
    id = Column(Integer, primary_key=True)
    thing_id = Column(Integer, ForeignKey("things.id"), nullable=False)
    made = Column(DateTime, nullable=False)


owned.install()


@pytest.fixture()
def Session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'u.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as s:
        s.add_all([User(id=1, email="a@example.com"), User(id=2, email="b@example.com"), User(id=3, email="c@example.com", status="removed")])
        s.commit()
    return factory


def row(Session, user_id):
    with Session() as s:
        u = s.get(User, user_id)
        return u.last_seen_at, u.active_days


def test_recording_sets_last_seen_and_counts_a_new_active_day_only_once_a_day(Session):
    seen = usage.LastSeen(Session)
    morning = datetime(2026, 3, 10, 8, 0)
    seen.record(1, now=morning)
    assert row(Session, 1) == (morning, 1)
    seen.record(1, now=morning.replace(hour=20))  # the same day: last seen moves, the day count does not
    assert row(Session, 1) == (morning.replace(hour=20), 1)
    seen.record(1, now=morning + timedelta(days=1))
    assert row(Session, 1)[1] == 2
    assert row(Session, 2) == (None, 0)  # nobody else was touched


def test_a_person_is_only_due_once_an_hour(Session):
    now = [1000.0]
    seen = usage.LastSeen(Session, every_seconds=3600, clock=lambda: now[0])
    assert seen.due(1) and seen.due(2)
    seen.record(1)
    assert not seen.due(1) and seen.due(2)
    now[0] += 3599
    assert not seen.due(1)
    now[0] += 2
    assert seen.due(1)


def test_a_failed_write_is_swallowed_and_not_retried_on_every_request(Session):
    def broken():
        raise RuntimeError("database is locked")

    seen = usage.LastSeen(broken)
    seen.record(1)  # must not raise
    assert not seen.due(1)


def test_counts_per_person_with_the_newest_date_and_the_last_activity(Session):
    with owned.unscoped(), Session() as s:
        s.add_all([Thing(owner_id=1, made=datetime(2026, 2, 1)), Thing(owner_id=1, made=datetime(2026, 2, 5)), Thing(owner_id=2, made=datetime(2026, 2, 3))])
        s.commit()
        s.get(User, 1).last_seen_at = datetime(2026, 2, 4)
        s.get(User, 2).last_seen_at = datetime(2026, 3, 1)
        s.commit()
    with owned.unscoped(), Session() as s:
        body = usage.build(s, User, {"things": usage.per_user(s, Thing.owner_id, Thing.made), "plain": usage.per_user(s, Thing.owner_id)})
    a, b, c = body["accounts"]
    assert [x["email"] for x in body["accounts"]] == ["a@example.com", "b@example.com", "c@example.com"]
    assert a["counts"] == {"things": 2, "plain": 2} and b["counts"]["things"] == 1 and c["counts"] == {"things": 0, "plain": 0}
    assert a["last_activity_at"] == "2026-02-05T00:00:00Z"  # a newer row than last seen
    assert b["last_activity_at"] == "2026-03-01T00:00:00Z"  # last seen newer than the row
    assert c["last_activity_at"] is None and c["last_seen_at"] is None and c["status"] == "removed"
    assert a["created_at"] == "2026-01-01T00:00:00Z" and a["active_days"] == 0


def test_a_where_narrows_what_is_counted(Session):
    with owned.unscoped(), Session() as s:
        s.add_all([Thing(owner_id=1, made=datetime(2026, 2, 1)), Thing(owner_id=1, made=datetime(2026, 5, 1)), Thing(owner_id=2, made=datetime(2026, 5, 2))])
        s.commit()
        got = usage.per_user(s, Thing.owner_id, Thing.made, where=Thing.made > datetime(2026, 3, 1))
    assert got == {1: (1, datetime(2026, 5, 1)), 2: (1, datetime(2026, 5, 2))}


def test_a_join_counts_rows_that_belong_to_a_person_through_something_else(Session):
    with owned.unscoped(), Session() as s:
        s.add_all([Thing(id=10, owner_id=1, made=datetime(2026, 2, 1)), Thing(id=11, owner_id=2, made=datetime(2026, 2, 2))])
        s.commit()
        s.add_all([Part(thing_id=10, made=datetime(2026, 3, 1)), Part(thing_id=10, made=datetime(2026, 3, 5)), Part(thing_id=11, made=datetime(2026, 3, 2))])
        s.commit()
        got = usage.per_user(s, Thing.owner_id, Part.made, source=Thing.__table__.join(Part.__table__, Part.thing_id == Thing.id))
    assert got == {1: (2, datetime(2026, 3, 5)), 2: (1, datetime(2026, 3, 2))}


def test_without_unscoped_an_owned_table_counts_nothing(Session):
    with owned.unscoped(), Session() as s:
        s.add(Thing(owner_id=1, made=datetime(2026, 2, 1)))
        s.commit()
    with Session() as s:
        assert usage.per_user(s, Thing.owner_id) == {}  # the reason an app's stats route runs inside owned.unscoped()


def test_the_gate_records_a_person_but_not_a_service_call(Session):
    seen = usage.LastSeen(Session)
    app = FastAPI()

    @app.get("/api/ping")
    def ping():
        return "pong"

    def account_for(email):
        return Account(id=1, email=email, is_admin=True)

    def service(request):
        return Account(id=2, email="svc@example.com", is_admin=True) if request.headers.get("x-service") else None

    accounts_gate.install(app, account_for=account_for, dev_user_email="dev@localhost.test", service_account=service, seen=seen)
    client = TestClient(app)
    assert client.get("/api/ping", headers={"x-service": "1"}).status_code == 200
    assert row(Session, 2) == (None, 0)  # a machine-to-machine call is not a person using the app
    assert client.get("/api/ping").status_code == 200
    assert row(Session, 1)[1] == 1
    client.get("/api/ping")
    assert row(Session, 1)[1] == 1  # not again within the hour


# --- telling the dashboard about a day of use ----------------------------------------------------------------------------


@pytest.fixture()
def announced(monkeypatch):
    """What the dashboard would be told, as (app, email, day); the background thread is run on the spot."""
    from shared_python import settings

    sent = []
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090")
    monkeypatch.setattr(usage, "_send_active_day", lambda app, email, day: sent.append((app, email, day)))
    monkeypatch.setattr(usage.threading, "Thread", lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    return sent


def test_the_first_visit_of_a_day_is_announced_once_with_that_days_date(Session, announced):
    seen = usage.LastSeen(Session, app="lists")
    seen.record(1, now=datetime(2026, 11, 20, 9, 0))
    seen.record(1, now=datetime(2026, 11, 20, 17, 0))  # the same day again
    seen.record(1, now=datetime(2026, 11, 21, 8, 0))  # the next day
    assert announced == [("lists", "a@example.com", "2026-11-20"), ("lists", "a@example.com", "2026-11-21")]


def test_nothing_is_announced_without_an_app_key_or_a_dashboard(Session, announced, monkeypatch):
    usage.LastSeen(Session).record(1, now=datetime(2026, 11, 20, 9, 0))  # no app key given
    assert announced == []
    from shared_python import settings

    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", None)
    usage.LastSeen(Session, app="lists").record(2, now=datetime(2026, 11, 20, 9, 0))
    assert announced == []


def test_the_announcement_is_the_app_the_address_and_the_day_to_the_dashboards_route(monkeypatch):
    import requests
    from shared_python import settings

    calls = []
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090/")
    monkeypatch.setattr(requests, "post", lambda url, json=None, timeout=None: calls.append((url, json, timeout)))
    usage._send_active_day("trips", "a@example.com", "2026-11-21")
    assert calls == [("http://127.0.0.1:8090/internal/active-day", {"app": "trips", "email": "a@example.com", "day": "2026-11-21"}, 2)]


def test_a_dashboard_that_does_not_answer_never_breaks_recording(Session, monkeypatch, caplog):
    import requests
    from shared_python import settings

    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090")

    def down(*args, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(requests, "post", down)
    usage._send_active_day("lists", "a@example.com", "2026-11-21")  # returns; only logged
    assert "Could not tell the dashboard" in caplog.text
    usage.LastSeen(Session, app="lists").record(1)  # and a real record still works, whatever the thread does
    assert row(Session, 1)[1] == 1
