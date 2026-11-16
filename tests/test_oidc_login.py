"""The sign-in flow: /auth/login, /auth/callback, /auth/logout against a stand-in
identity provider. The provider is only settings, so the stand-in is a discovery
document, a token endpoint and a signing key. The points that matter: PKCE and state
and nonce are really checked, a tampered or foreign ID token never signs anyone in,
nobody can be bounced to another site, and nothing is reachable until it is configured."""
import base64
import hashlib
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from shared_python import auth, oidc_login, settings

ISSUER = "https://login.example.com"
CLIENT = "client-123"
DEV = "dev@localhost.test"
DISCOVERY = {
    "issuer": ISSUER + "/",
    "authorization_endpoint": ISSUER + "/authorize",
    "token_endpoint": ISSUER + "/oauth/token",
    "end_session_endpoint": ISSUER + "/oidc/logout",
    "jwks_uri": ISSUER + "/keys",
}

app = FastAPI()
app.include_router(oidc_login.router)


@app.get("/who")
def who(request: Request):
    return {"email": auth.request_email(request, DEV)}


@app.get("/page")
def page(request: Request):
    return oidc_login.redirect_if_signed_out(request, DEV) or {"page": "ok"}


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Provider:
    """What the stand-in provider does when the app calls it."""

    def __init__(self, key):
        self.key = key
        self.token_calls = []
        self.token_status = 200
        self.discovery_calls = 0
        self.down = False
        self.claims = {}  # overrides for the ID token
        self.nonce_override = None
        self.discovery = dict(DISCOVERY)

    def get(self, url, **kw):
        assert url == ISSUER + "/.well-known/openid-configuration", url
        self.discovery_calls += 1
        if self.down:
            raise requests.ConnectionError("down")
        return _Reply(200, self.discovery)

    def post(self, url, data=None, **kw):
        assert url == ISSUER + "/oauth/token"
        self.token_calls.append(data)
        if self.token_status != 200:
            return _Reply(self.token_status, {"error": "invalid_grant"})
        claims = {
            "iss": ISSUER + "/", "aud": CLIENT, "exp": int(time.time()) + 3600, "email": "alice@example.com",
            "email_verified": True, "nonce": self.nonce_override or self.nonce, **self.claims,
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        return _Reply(200, {"id_token": jwt.encode(claims, self.key, algorithm="RS256"), "access_token": "x"})

    nonce = None


class _Reply:
    def __init__(self, status, body):
        self.status_code, self.body = status, body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        return self.body


@pytest.fixture()
def provider(monkeypatch, key):
    p = Provider(key)
    monkeypatch.setattr(requests, "get", p.get)
    monkeypatch.setattr(requests, "post", p.post)
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", CLIENT)
    monkeypatch.setattr(settings, "OIDC_CLIENT_SECRET", "s3cret")
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", CLIENT)
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _token: key.public_key())
    return p


@pytest.fixture()
def client(provider):
    return TestClient(app, follow_redirects=False)


@pytest.fixture()
def prod(monkeypatch, provider):
    monkeypatch.setattr(settings, "ENV", "production")
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


def start(client, provider, **params):
    """Visit /auth/login; return the provider-bound query and remember its nonce."""
    resp = client.get("/auth/login", params=params)
    assert resp.status_code == 302
    query = {k: v[0] for k, v in parse_qs(urlparse(resp.headers["location"]).query).items()}
    provider.nonce = query["nonce"]
    return resp, query


def finish(client, query, **extra):
    return client.get("/auth/callback", params={"code": "the-code", "state": query["state"], **extra})


# --- going to the provider ---------------------------------------------------------


def test_login_sends_the_browser_to_the_provider_with_pkce_state_and_nonce(client, provider):
    resp, q = start(client, provider)
    assert resp.headers["location"].startswith(ISSUER + "/authorize?")
    assert q["response_type"] == "code" and q["client_id"] == CLIENT
    assert q["redirect_uri"] == "http://testserver/auth/callback"
    assert q["scope"] == "openid email profile"
    assert q["code_challenge_method"] == "S256" and q["state"] and q["nonce"]
    assert resp.headers["cache-control"] == "no-store"
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/auth" in cookie


def test_the_redirect_address_is_https_in_production_and_the_cookie_is_secure(prod, provider):
    resp, q = start(prod, provider)
    assert q["redirect_uri"] == "https://testserver/auth/callback"
    assert "secure" in resp.headers["set-cookie"].lower()


def test_a_login_hint_is_passed_along_for_prefilling_the_email(client, provider):
    _, q = start(client, provider, login_hint="bob@example.com")
    assert q["login_hint"] == "bob@example.com"


def test_scopes_are_a_setting(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_SCOPES", "openid email")
    assert start(client, provider)[1]["scope"] == "openid email"


def test_a_provider_that_cant_be_reached_gives_a_plain_page_not_a_crash(client, provider):
    provider.down = True
    resp = client.get("/auth/login")
    assert resp.status_code == 503 and "unavailable" in resp.text.lower()


def test_the_discovery_document_is_fetched_once_not_per_visit(client, provider):
    start(client, provider)
    start(client, provider)
    assert provider.discovery_calls == 1


# --- coming back -------------------------------------------------------------------


def test_the_whole_flow_signs_the_person_in_and_the_session_cookie_works(client, provider):
    _, q = start(client, provider, next="/list.html?id=3")
    resp = finish(client, q)
    assert resp.status_code == 302 and resp.headers["location"] == "/list.html?id=3"
    cookies = resp.headers.get_list("set-cookie")
    session = next(c for c in cookies if c.startswith("oidc_session="))
    assert "httponly" in session.lower() and "samesite=lax" in session.lower()
    assert client.get("/who").json()["email"] == "alice@example.com"


def test_the_code_is_exchanged_with_the_matching_pkce_verifier_and_the_secret(client, provider):
    _, q = start(client, provider)
    finish(client, q)
    sent = provider.token_calls[0]
    assert sent["grant_type"] == "authorization_code" and sent["code"] == "the-code"
    assert sent["client_id"] == CLIENT and sent["client_secret"] == "s3cret"
    assert sent["redirect_uri"] == "http://testserver/auth/callback"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(sent["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    assert challenge == q["code_challenge"]


def test_no_secret_is_sent_when_the_provider_application_has_none(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_CLIENT_SECRET", None)
    _, q = start(client, provider)
    finish(client, q)
    assert "client_secret" not in provider.token_calls[0]


@pytest.mark.parametrize("evil", ["//evil.example.com", "https://evil.example.com", "/\\evil.example.com", "evil", ""])
def test_nobody_can_be_sent_to_another_site_after_signing_in(client, provider, evil):
    _, q = start(client, provider, next=evil)
    assert finish(client, q).headers["location"] == "/"


def test_the_session_lasts_as_long_as_the_id_token(client, provider):
    provider.claims = {"exp": int(time.time()) + 1000}
    _, q = start(client, provider)
    cookies = finish(client, q).headers.get_list("set-cookie")
    session = next(c for c in cookies if c.startswith("oidc_session="))
    max_age = int(session.lower().split("max-age=")[1].split(";")[0])
    assert 990 <= max_age <= 1000


def test_the_pending_login_cookie_is_cleared_once_used(client, provider):
    _, q = start(client, provider)
    cookies = finish(client, q).headers.get_list("set-cookie")
    assert any(c.startswith("oidc_login=") and "max-age=0" in c.lower() for c in cookies)


def test_a_wrong_state_is_refused_and_signs_nobody_in(client, provider):
    _, q = start(client, provider)
    resp = client.get("/auth/callback", params={"code": "c", "state": "forged"})
    assert resp.status_code == 400 and "oidc_session" not in resp.headers.get("set-cookie", "")
    assert provider.token_calls == []  # never even exchanged the code


def test_a_callback_with_no_pending_login_is_refused(provider):
    fresh = TestClient(app, follow_redirects=False)  # a browser that never started a login
    assert fresh.get("/auth/callback", params={"code": "c", "state": "s"}).status_code == 400


def test_a_callback_with_no_code_is_refused(client, provider):
    _, q = start(client, provider)
    assert client.get("/auth/callback", params={"state": q["state"]}).status_code == 400


def test_a_garbled_login_cookie_is_refused(client, provider):
    client.cookies.set("oidc_login", "not-base64-json!!", path="/auth")
    assert client.get("/auth/callback", params={"code": "c", "state": "s"}).status_code == 400


def test_an_error_from_the_provider_is_shown_plainly_and_its_text_is_not_echoed(client, provider):
    _, q = start(client, provider)
    resp = client.get("/auth/callback", params={"error": "access_denied", "error_description": "<script>alert(1)</script>"})
    assert resp.status_code == 400 and "<script>" not in resp.text


def test_a_refused_code_exchange_is_reported_and_signs_nobody_in(client, provider):
    _, q = start(client, provider)
    provider.token_status = 400
    resp = finish(client, q)
    assert resp.status_code == 400 and "oidc_session" not in resp.headers.get("set-cookie", "")


def test_an_id_token_for_another_sign_in_is_refused(client, provider):
    _, q = start(client, provider)
    provider.nonce_override = "someone-elses-nonce"
    resp = finish(client, q)
    assert resp.status_code == 401 and "oidc_session" not in resp.headers.get("set-cookie", "")


def test_an_id_token_for_another_application_is_refused(client, provider):
    _, q = start(client, provider)
    provider.claims = {"aud": "another-client"}
    assert finish(client, q).status_code == 401


def test_an_id_token_from_another_issuer_is_refused(client, provider):
    _, q = start(client, provider)
    provider.claims = {"iss": "https://evil.example.com"}
    assert finish(client, q).status_code == 401


def test_an_expired_id_token_is_refused(client, provider):
    _, q = start(client, provider)
    provider.claims = {"exp": int(time.time()) - 10}
    assert finish(client, q).status_code == 401


def test_an_unverified_email_never_signs_anyone_in(client, provider):
    _, q = start(client, provider)
    provider.claims = {"email_verified": False}
    resp = finish(client, q)
    assert resp.status_code == 403 and "oidc_session" not in resp.headers.get("set-cookie", "")  # told what to do, not signed in


def test_an_id_token_with_no_email_is_refused(client, provider):
    _, q = start(client, provider)
    provider.claims = {"email": None}
    assert finish(client, q).status_code == 401


# --- leaving -----------------------------------------------------------------------


def test_logout_clears_the_session_and_ends_the_providers_too(client, provider):
    _, q = start(client, provider)
    finish(client, q)
    resp = client.get("/auth/logout")
    target = urlparse(resp.headers["location"])
    assert resp.status_code == 302 and (target.scheme + "://" + target.netloc + target.path) == ISSUER + "/oidc/logout"
    params = parse_qs(target.query)
    assert params["post_logout_redirect_uri"] == ["http://testserver/"] and params["client_id"] == [CLIENT]
    assert params["id_token_hint"]
    assert any(c.startswith("oidc_session=") and "max-age=0" in c.lower() for c in resp.headers.get_list("set-cookie"))


def test_logout_without_a_provider_logout_endpoint_just_goes_home(client, provider):
    del provider.discovery["end_session_endpoint"]
    assert client.get("/auth/logout").headers["location"] == "http://testserver/"


# --- not configured ----------------------------------------------------------------


@pytest.mark.parametrize("path", ["/auth/login", "/auth/callback", "/auth/logout"])
def test_nothing_is_reachable_until_the_flow_is_configured(client, provider, monkeypatch, path):
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", None)
    assert client.get(path).status_code == 404


# --- sending signed-out visitors to sign in ------------------------------------------


def test_a_signed_out_visitor_to_a_page_is_sent_to_sign_in_and_back(prod, provider):
    resp = prod.get("/page?x=1")
    assert resp.status_code == 302 and resp.headers["location"] == "/auth/login?next=%2Fpage%3Fx%3D1"


def test_a_signed_in_visitor_just_sees_the_page(prod, provider):
    _, q = start(prod, provider)
    finish(prod, q)
    assert prod.get("/page").json() == {"page": "ok"}


def test_an_expired_session_is_sent_back_to_sign_in(prod, provider):
    prod.cookies.set("oidc_session", jwt.encode({"iss": ISSUER, "aud": CLIENT, "exp": int(time.time()) - 5, "email": "a@b.co"}, provider.key, algorithm="RS256"))
    assert prod.get("/page").status_code == 302


def test_pages_are_untouched_when_the_flow_is_not_configured(prod, provider, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", None)
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", "t.cloudflareaccess.com")
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", "aud")
    assert oidc_login.redirect_if_signed_out(_request_stub()) is None


def test_locally_a_visitor_with_no_session_is_the_dev_user_and_not_redirected(client, provider):
    assert client.get("/page").json() == {"page": "ok"}
    assert client.get("/who").json()["email"] == DEV


def test_locally_a_real_session_wins_over_the_dev_user(client, provider):
    _, q = start(client, provider)
    finish(client, q)
    assert client.get("/who").json()["email"] == "alice@example.com"


def test_locally_a_bare_bearer_token_is_still_ignored(client, provider):
    token = jwt.encode({"iss": ISSUER, "aud": CLIENT, "exp": int(time.time()) + 60, "email": "mallory@example.com"}, provider.key, algorithm="RS256")
    assert client.get("/who", headers={"Authorization": f"Bearer {token}"}).json()["email"] == DEV


def _request_stub():
    class Stub:
        headers: dict = {}
        cookies: dict = {}

    return Stub()


# --- moving between providers: two issuers side by side -----------------------------


def test_either_of_two_configured_issuers_signs_people_in_and_the_first_is_where_login_goes(prod, provider, monkeypatch, key):
    other = "https://new-login.example.org"
    monkeypatch.setattr(settings, "OIDC_ISSUER", f"{ISSUER}/, {other}")
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", f"{CLIENT},client-999")
    make = lambda iss: jwt.encode({"iss": iss, "aud": "client-999", "exp": int(time.time()) + 60, "email": "alice@example.com"}, key, algorithm="RS256")
    assert prod.get("/who", headers={"Authorization": f"Bearer {make(ISSUER)}"}).status_code == 200
    assert prod.get("/who", headers={"Authorization": f"Bearer {make(other)}"}).status_code == 200
    assert prod.get("/who", headers={"Authorization": f"Bearer {make('https://evil.example.com')}"}).status_code == 401
    assert prod.get("/auth/login").headers["location"].startswith(ISSUER + "/authorize?")
