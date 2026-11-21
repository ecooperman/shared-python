"""An app tells the dashboard when someone's access changes - after the change is committed, only when it really changed, and never
in a way that can get in the change's way."""
import pytest
import requests
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base

from shared_python import access_events, settings

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")
    note = Column(String)


access_events.install(User)


@pytest.fixture()
def told(monkeypatch):
    """Every address the dashboard would have been told about (the thread is run on the spot)."""
    sent = []
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090")
    monkeypatch.setattr(access_events, "_post", lambda email: sent.append(email))
    monkeypatch.setattr(access_events.threading, "Thread", lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    return sent


@pytest.fixture()
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_a_new_user_is_announced_once_the_change_is_committed(session, told):
    session.add(User(email="ann@example.com"))
    session.flush()
    assert told == []  # not before it is committed: the dashboard could ask the app and still hear "no account"
    session.commit()
    assert told == ["ann@example.com"]


def test_a_change_of_status_is_announced_and_another_change_is_not(session, told):
    user = User(email="ann@example.com")
    session.add(user)
    session.commit()
    told.clear()
    user.note = "just a note"
    session.commit()
    assert told == []
    user.status = "removed"
    session.commit()
    assert told == ["ann@example.com"]


def test_a_rolled_back_change_is_not_announced(session, told):
    session.add(User(email="ann@example.com"))
    session.flush()
    session.rollback()
    session.commit()
    assert told == []


def test_several_changes_in_one_commit_tell_about_each_person_once(session, told):
    ann = User(email="ann@example.com")
    session.add_all([ann, User(email="bob@example.com")])
    session.flush()
    ann.status = "removed"
    session.commit()
    assert sorted(told) == ["ann@example.com", "bob@example.com"]


def test_nothing_is_sent_when_no_dashboard_is_set(session, monkeypatch):
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", None)
    monkeypatch.setattr(requests, "post", lambda *a, **k: pytest.fail("a request went out"))
    session.add(User(email="ann@example.com"))
    session.commit()


def test_a_dashboard_that_does_not_answer_never_breaks_the_change(monkeypatch, caplog):
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090")

    def down(*args, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(requests, "post", down)
    access_events._post("ann@example.com")  # returns; the failure is only logged
    assert "Could not tell the dashboard" in caplog.text


def test_the_message_is_just_the_email_to_the_dashboards_route(monkeypatch):
    calls = []
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090/")
    monkeypatch.setattr(requests, "post", lambda url, json=None, timeout=None: calls.append((url, json, timeout)))
    access_events._post("ann@example.com")
    assert calls == [("http://127.0.0.1:8090/internal/access-changed", {"email": "ann@example.com"}, 2)]
