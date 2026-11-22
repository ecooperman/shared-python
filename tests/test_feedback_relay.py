"""An app's Send feedback route passes the message to the dashboard with the app's key and only the person's sign-in cookie."""
import pytest
import requests
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from shared_python import auth, feedback_relay, settings


class Reply:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body if body is not None else {}

    def json(self):
        if self._body == "not json":
            raise ValueError("no")
        return self._body


class Calls(list):
    state: dict = {}


@pytest.fixture()
def sent(monkeypatch):
    calls = Calls()
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090")
    monkeypatch.setattr(auth, "oidc_cookie_name", lambda: "oidc_session")
    state = {"reply": Reply(200, {"id": 1})}

    def post(url, json=None, headers=None, timeout=None, allow_redirects=True):
        calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout, "allow_redirects": allow_redirects})
        if isinstance(state["reply"], Exception):
            raise state["reply"]
        return state["reply"]

    monkeypatch.setattr(requests, "post", post)
    calls.state = state
    return calls


def make(dependencies=()):
    app = FastAPI()
    feedback_relay.install(app, "lists", dependencies=dependencies)
    return TestClient(app)


BODY = {"kind": "problem", "body": "It broke", "page": "/list.html"}


def test_the_message_goes_to_the_dashboard_with_the_apps_key_and_only_the_sign_in_cookie(sent):
    client = make()
    client.cookies.set("oidc_session", "TOKEN")
    client.cookies.set("theme", "dark")
    resp = client.post("/api/feedback", json=BODY)
    assert resp.status_code == 200 and resp.json() == {"id": 1}
    call = sent[0]
    assert call["url"] == "http://127.0.0.1:8090/internal/feedback"
    assert call["json"] == {"app": "lists", **BODY}
    assert call["headers"] == {"Cookie": "oidc_session=TOKEN"} and call["allow_redirects"] is False and call["timeout"] == 5


def test_the_app_key_cannot_be_chosen_by_the_sender(sent):
    make().post("/api/feedback", json={**BODY, "app": "finances"})
    assert sent[0]["json"]["app"] == "lists"


def test_the_apps_own_gate_comes_first(sent):
    def refuse():
        raise HTTPException(status_code=403, detail="No account")

    assert make([Depends(refuse)]).post("/api/feedback", json=BODY).status_code == 403
    assert sent == []  # nothing was passed on


def test_a_sentence_from_the_dashboard_reaches_the_person_and_anything_else_is_a_502(sent):
    client = make()
    sent.state["reply"] = Reply(400, {"detail": "Write a few words first."})
    resp = client.post("/api/feedback", json=BODY)
    assert resp.status_code == 400 and resp.json()["detail"] == "Write a few words first."
    sent.state["reply"] = Reply(429, {"detail": "You have sent 10 messages today."})
    assert client.post("/api/feedback", json=BODY).status_code == 429
    sent.state["reply"] = Reply(401, {"detail": "Not signed in"})
    assert client.post("/api/feedback", json=BODY).status_code == 401
    for odd in (Reply(500, "not json"), Reply(404, {"detail": "Not Found"}), Reply(403, {"detail": "x"})):
        sent.state["reply"] = odd
        assert client.post("/api/feedback", json=BODY).status_code == 502


def test_a_dashboard_that_does_not_answer_is_a_502_with_a_sentence(sent):
    sent.state["reply"] = requests.ConnectionError("down")
    resp = make().post("/api/feedback", json=BODY)
    assert resp.status_code == 502 and "try again" in resp.json()["detail"]


def test_without_a_dashboard_set_it_says_so(monkeypatch):
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", None)
    resp = make().post("/api/feedback", json=BODY)
    assert resp.status_code == 503 and "isn't set up" in resp.json()["detail"]
