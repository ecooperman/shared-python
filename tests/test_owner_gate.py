"""The owner-only gate for apps with no accounts of their own. The point of these tests: with the front door
in use, NOTHING in the app answers anyone but an administrator (pages, API, static files, unknown paths, other
methods), the one machine-to-machine exception is as narrow as the app makes it, and a missing administrator
list locks everyone out instead of letting everyone in."""
import hmac
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.testclient import TestClient

from shared_python import auth, owner_gate, settings

ISSUER = "https://login.example.com"
CLIENT = "client-123"
FRONT = "https://dashboard.example.org"
ADMINS = {"owner@example.com"}
DEV = "dev@localhost.test"
TOKEN = "service-secret"


def build(admins=lambda: ADMINS, service_access=None, public_paths=()):
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    def home():
        return "<h1>private home</h1>"

    @app.get("/style.css")
    def css():
        return PlainTextResponse("body{}")

    @app.get("/api/data")
    def data():
        return {"secret": 42}

    @app.post("/api/data")
    def write():
        return {"written": True}

    @app.delete("/api/data/{item}")
    def remove(item: int):
        return {"deleted": item}

    @app.get("/api/plans")
    def plans():
        return {"plans": []}

    @app.get("/manifest.json")
    def manifest():
        return {"name": "app"}

    @app.get("/icons/{name}")
    def icon(name: str):
        return PlainTextResponse("png")

    owner_gate.install(app, admin_emails=admins, dev_user_email=DEV, service_access=service_access, public_paths=public_paths)
    return app


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def session(key, email, exp_in=300):
    return jwt.encode(
        {"iss": ISSUER, "aud": CLIENT, "exp": int(time.time()) + exp_in, "email": email, "email_verified": True},
        key, algorithm="RS256",
    )


@pytest.fixture()
def production(monkeypatch, key):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", CLIENT)
    monkeypatch.setattr(settings, "OIDC_LOGIN_URL", FRONT + "/auth/login")
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _t: key.public_key())


def client_for(app, **kw):
    return TestClient(app, base_url="https://private.example.org", follow_redirects=False, **kw)


# --- the administrator gets in ------------------------------------------------------------------------------------


def test_an_administrator_with_the_shared_cookie_gets_everything(production, key):
    c = client_for(build())
    c.cookies.set("oidc_session", session(key, "Owner@Example.com"))  # case does not matter
    assert c.get("/").status_code == 200 and c.get("/style.css").status_code == 200
    assert c.get("/api/data").json() == {"secret": 42} and c.post("/api/data").status_code == 200


# --- everyone else does not -------------------------------------------------------------------------------------------


def test_a_signed_out_visitor_to_a_page_is_sent_to_the_front_door_and_back(production):
    resp = client_for(build()).get("/?tab=2")
    assert resp.status_code == 302
    assert resp.headers["location"].startswith(FRONT + "/auth/login?next=")
    assert "https%3A%2F%2Fprivate.example.org%2F%3Ftab%3D2" in resp.headers["location"]


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/data"), ("POST", "/api/data"), ("DELETE", "/api/data/1"), ("GET", "/api/plans"), ("PUT", "/api/data"),
    ("GET", "/api/anything-at-all"),
])
def test_signed_out_api_calls_are_a_401_and_never_a_redirect(production, method, path):
    resp = client_for(build()).request(method, path)
    assert resp.status_code == 401 and "secret" not in resp.text


def test_a_signed_out_request_for_a_file_is_sent_to_sign_in_too(production):
    assert client_for(build()).get("/style.css").status_code == 302


def test_a_signed_in_person_who_is_not_an_administrator_is_refused_everywhere(production, key):
    c = client_for(build())
    c.cookies.set("oidc_session", session(key, "stranger@example.com"))
    page = c.get("/")
    assert page.status_code == 403 and "This app is private" in page.text and "stranger@example.com" in page.text
    assert "private home" not in page.text and f'href="{FRONT}/auth/logout"' in page.text
    for method, path in [("GET", "/api/data"), ("POST", "/api/data"), ("DELETE", "/api/data/1"), ("GET", "/style.css")]:
        resp = c.request(method, path)
        assert resp.status_code == 403 and "secret" not in resp.text and ": 42" not in resp.text


def test_an_expired_session_is_treated_as_signed_out(production, key):
    c = client_for(build())
    c.cookies.set("oidc_session", session(key, "owner@example.com", exp_in=-10))
    assert c.get("/").status_code == 302 and c.get("/api/data").status_code == 401


def test_an_unknown_path_and_a_wrong_method_are_gated_before_they_are_a_404_or_405(production):
    c = client_for(build())
    assert c.get("/no/such/thing").status_code == 302  # the gate answers first, so the app's layout is not revealed
    assert c.request("PATCH", "/api/data").status_code == 401


def test_an_unverified_email_is_never_an_administrator(production, key):
    c = client_for(build())
    c.cookies.set("oidc_session", jwt.encode(
        {"iss": ISSUER, "aud": CLIENT, "exp": int(time.time()) + 300, "email": "owner@example.com", "email_verified": False},
        key, algorithm="RS256"))
    assert c.get("/api/data").status_code == 401


def test_a_token_for_another_application_does_not_get_in(production, key):
    c = client_for(build())
    c.cookies.set("oidc_session", jwt.encode(
        {"iss": ISSUER, "aud": "someone-elses-client", "exp": int(time.time()) + 300, "email": "owner@example.com", "email_verified": True},
        key, algorithm="RS256"))
    assert c.get("/api/data").status_code == 401


# --- failing closed ------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("admins", [lambda: set(), lambda: [], lambda: {"", "  "}])
def test_with_no_administrator_configured_in_production_nobody_gets_in(production, key, admins):
    c = client_for(build(admins=admins))
    c.cookies.set("oidc_session", session(key, "owner@example.com"))
    assert c.get("/api/data").status_code == 503 and c.get("/").status_code == 503


def test_in_production_with_no_sign_in_configured_everything_is_refused(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    assert client_for(build()).get("/api/data").status_code == 503


# --- the narrow machine-to-machine exception ---------------------------------------------------------------------------


def only_plans_reads(request: Request) -> bool:
    supplied = request.headers.get("x-service-token", "")
    return (
        request.method == "GET" and request.url.path == "/api/plans"
        and hmac.compare_digest(supplied.encode(), TOKEN.encode())
    )


def test_the_exception_lets_exactly_the_agreed_call_through(production):
    c = client_for(build(service_access=only_plans_reads))
    assert c.get("/api/plans", headers={"X-Service-Token": TOKEN}).status_code == 200


@pytest.mark.parametrize("method,path,token", [
    ("GET", "/api/plans", "wrong"), ("GET", "/api/plans", ""), ("POST", "/api/plans", TOKEN),
    ("GET", "/api/data", TOKEN), ("DELETE", "/api/data/1", TOKEN), ("GET", "/", TOKEN),
])
def test_anything_else_with_or_without_a_token_is_still_refused(production, method, path, token):
    headers = {"X-Service-Token": token} if token else {}
    resp = client_for(build(service_access=only_plans_reads)).request(method, path, headers=headers)
    assert resp.status_code in (401, 302, 405) and "secret" not in resp.text and ": 42" not in resp.text


# --- locally and alongside Cloudflare ---------------------------------------------------------------------------------


def test_locally_the_dev_user_is_let_in_when_it_is_an_administrator():
    c = client_for(build(admins=lambda: {DEV}))
    assert c.get("/api/data").status_code == 200


def test_locally_the_dev_user_is_refused_when_it_is_not_an_administrator():
    assert client_for(build()).get("/api/data").status_code == 403


def test_a_cloudflare_token_for_an_administrator_still_works_during_the_move(production, key, monkeypatch):
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", "team.cloudflareaccess.com")
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", "cf-aud")
    monkeypatch.setattr(auth, "_signing_key", lambda _t: key.public_key())
    token = jwt.encode({"email": "owner@example.com", "aud": ["cf-aud"], "exp": int(time.time()) + 300}, key, algorithm="RS256")
    other = jwt.encode({"email": "stranger@example.com", "aud": ["cf-aud"], "exp": int(time.time()) + 300}, key, algorithm="RS256")
    c = client_for(build())
    assert c.get("/api/data", headers={"Cf-Access-Jwt-Assertion": token}).status_code == 200
    assert c.get("/api/data", headers={"Cf-Access-Jwt-Assertion": other}).status_code == 403


def test_the_plain_cloudflare_email_header_is_never_trusted_in_production(production):
    resp = client_for(build()).get("/api/data", headers={"Cf-Access-Authenticated-User-Email": "owner@example.com"})
    assert resp.status_code == 401


# --- the few files a browser fetches without a cookie -------------------------------------------------------------------

PUBLIC = ("/manifest.json", "/icons/")


def test_the_listed_public_files_need_no_sign_in(production):
    c = client_for(build(public_paths=PUBLIC))
    assert c.get("/manifest.json").status_code == 200 and c.get("/icons/apple-touch-icon.png").status_code == 200
    assert c.head("/manifest.json").status_code in (200, 405)  # allowed through the gate; the app decides about HEAD


@pytest.mark.parametrize("method,path", [
    ("POST", "/manifest.json"), ("DELETE", "/icons/x.png"), ("GET", "/manifest.json.bak"), ("GET", "/manifest.jsonx"),
    ("GET", "/icons"), ("GET", "/icons/"), ("GET", "/api/data"), ("GET", "/"),
])
def test_nothing_beyond_the_listed_files_is_public(production, method, path):
    resp = client_for(build(public_paths=PUBLIC)).request(method, path)
    assert resp.status_code in (302, 401) and "secret" not in resp.text


@pytest.mark.parametrize("path", ["/icons/../api/data", "/icons/%2e%2e/api/data", "/icons//../api/data", "/icons/..%2fapi/data", "/icons/a\\..\\b"])
def test_a_crafted_path_cannot_wander_out_of_a_public_folder(production, path):
    resp = client_for(build(public_paths=PUBLIC)).get(path)
    assert resp.status_code in (302, 401, 404) and "secret" not in resp.text and ": 42" not in resp.text
