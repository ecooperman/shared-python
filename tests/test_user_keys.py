"""An app fetches a person's key from the dashboard with THEIR cookie, only while they are signed in, and holds it in memory only."""
import threading

import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shared_python import auth, key_providers, settings, user_keys


class Reply:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body

    def json(self):
        if self._body == "not json":
            raise ValueError("no")
        return self._body


class Dashboard(list):
    reply = None


@pytest.fixture()
def dashboard(monkeypatch):
    calls = Dashboard()
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090")
    monkeypatch.setattr(auth, "oidc_cookie_name", lambda: "oidc_session")
    calls.reply = Reply(200, {"key": "sk-secret"})

    def get(url, headers=None, timeout=None, allow_redirects=True):
        calls.append({"url": url, "headers": headers, "timeout": timeout, "allow_redirects": allow_redirects})
        if isinstance(calls.reply, Exception):
            raise calls.reply
        return calls.reply

    monkeypatch.setattr(requests, "get", get)
    return calls


def make_app():
    app = FastAPI()
    user_keys.install(app)

    @app.get("/use")
    def use():
        return {"first": user_keys.fetch("anthropic"), "again": user_keys.fetch("anthropic"), "status": user_keys.status()}

    return TestClient(app)


def test_the_key_is_fetched_with_only_the_persons_sign_in_cookie_and_once_per_request(dashboard):
    client = make_app()
    client.cookies.set("oidc_session", "TOKEN")
    client.cookies.set("theme", "dark")
    dashboard.reply = Reply(200, {"key": "sk-secret"})
    got = client.get("/use")
    assert got.json()["first"] == "sk-secret" and got.json()["again"] == "sk-secret"
    keys = [c for c in dashboard if c["url"].endswith("/internal/keys/anthropic")]
    assert len(keys) == 1  # the second ask is answered from memory
    assert keys[0]["headers"] == {"Cookie": "oidc_session=TOKEN"} and keys[0]["allow_redirects"] is False and keys[0]["timeout"] == 5


def test_nothing_is_kept_between_requests(dashboard):
    client = make_app()
    client.cookies.set("oidc_session", "A")
    client.get("/use")
    client.cookies.set("oidc_session", "B", )
    before = len(dashboard)
    client.get("/use")
    assert len(dashboard) > before  # a new request asks again, as whoever it is now


def test_no_saved_key_is_none_and_a_signed_out_answer_is_a_401(dashboard):
    client = make_app()
    dashboard.reply = Reply(404, {})
    assert client.get("/use").json()["first"] is None
    dashboard.reply = Reply(401, {})
    assert client.get("/use").status_code == 401


def test_a_dashboard_that_cannot_be_reached_is_a_503_with_a_sentence_not_no_key(dashboard):
    client = make_app()
    for reply in (requests.ConnectionError("down"), Reply(500, {}), Reply(200, "not json")):
        dashboard.reply = reply
        got = client.get("/use")
        assert got.status_code == 503 and "try again" in got.json()["detail"]


def test_without_a_dashboard_set_it_says_so(monkeypatch):
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", None)
    got = make_app().get("/use")
    assert got.status_code == 503 and "aren't set up" in got.json()["detail"]


def test_work_in_a_thread_uses_the_session_it_was_given_and_the_key_is_not_fetched_again(dashboard):
    seen = {}
    session = None

    def request_part():
        nonlocal session
        session = user_keys.KeySession("oidc_session=TOKEN")
        with user_keys.use(session):
            seen["in_request"] = user_keys.fetch("anthropic")  # fetched while they are signed in

    request_part()
    calls_after_request = len(dashboard)

    def worker():
        with user_keys.use(session):
            seen["in_thread"] = user_keys.fetch("anthropic")

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert seen == {"in_request": "sk-secret", "in_thread": "sk-secret"} and len(dashboard) == calls_after_request
    assert user_keys.fetch("anthropic") is None  # outside any request there is no one to fetch for


def test_status_lists_what_they_saved_never_the_keys(dashboard):
    dashboard.reply = Reply(200, {"keys": {"anthropic": {"last4": "wxyz", "added_at": "2026-11-23T10:00:00"}}})
    got = make_app().get("/use").json()["status"]
    assert got == {"anthropic": {"last4": "wxyz", "added_at": "2026-11-23T10:00:00"}}


# --- checking a key before it is saved -------------------------------------------------------------------------------------------


def test_a_key_the_service_refuses_or_cannot_check_is_reported_in_words(monkeypatch):
    class R:
        def __init__(self, status):
            self.status_code, self.ok, self.headers = status, 200 <= status < 300, {"content-type": "text/plain"}

    monkeypatch.setattr(requests, "get", lambda *a, **k: R(401))
    assert key_providers.verify("anthropic", "sk-x")[0] is False
    monkeypatch.setattr(requests, "get", lambda *a, **k: R(200))
    assert key_providers.verify("anthropic", "sk-x") == (True, "")
    monkeypatch.setattr(requests, "get", lambda *a, **k: R(500))
    assert key_providers.verify("anthropic", "sk-x")[0] is None

    def down(*a, **k):
        raise requests.ConnectionError("https://api.anthropic.com/?key=sk-LEAK")

    monkeypatch.setattr(requests, "get", down)
    verified, why = key_providers.verify("anthropic", "sk-x")
    assert verified is None and "Couldn't reach Anthropic" in why and "LEAK" not in why  # the library's message (it can carry the key) is never shown


def test_a_request_with_no_sign_in_cookie_in_production_has_no_key_and_asks_nothing(dashboard, monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    got = make_app().get("/use").json()  # no cookie set: the extension's token door, say
    assert got == {"first": None, "again": None, "status": {}} and len(dashboard) == 0
