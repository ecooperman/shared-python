"""One front door for every app. The dashboard does the sign-in and sets the session cookie for the
whole parent domain; every other app only checks that cookie and sends signed-out visitors there.
The points that matter: a return address can only ever be a host on the allow-list (the open-redirect
guard, tried with every trick), the cookie really is domain-wide and is removed with the same
scope, and an app in verify-only mode holds no client id yet still signs people in from the cookie."""
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
FRONT = "https://dashboard.example.org"

# --- a stand-in front door (does the sign-in) and a stand-in app (verify-only) --------------

front_door = FastAPI()
front_door.include_router(oidc_login.router)

app = FastAPI()


@app.get("/who")
def who(request: Request):
    return {"email": auth.request_email(request, DEV)}


@app.get("/page")
def page(request: Request):
    return oidc_login.redirect_if_signed_out(request, DEV) or {"page": "ok"}


@app.get("/logout-url")
def logout_link(request: Request):
    return {"url": oidc_login.logout_url(request)}


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def id_token(key, email="alice@example.com", exp_in=300):
    return jwt.encode(
        {"iss": ISSUER, "aud": CLIENT, "exp": int(time.time()) + exp_in, "email": email, "email_verified": True},
        key, algorithm="RS256",
    )


@pytest.fixture()
def prod_hosts(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "OIDC_RETURN_HOSTS", ".example.org")


# --- the return address: an allow-listed host, nothing else ---------------------------------


@pytest.mark.parametrize("good", [
    "/", "/list.html?id=3", "https://lists.example.org/", "https://trips.example.org/trip.html?id=2&x=y",
    "https://LISTS.example.org/Path", "https://a.b.example.org/x",
])
def test_paths_and_addresses_on_allowed_hosts_are_kept(prod_hosts, good):
    assert oidc_login.safe_next(good) == good


@pytest.mark.parametrize("evil", [
    "https://evil.example.com/", "https://example.org/", "https://evil-example.org/", "https://example.org.evil.com/",
    "https://lists.example.org.evil.com/", "https://evil.com/lists.example.org", "https://evil.com#.example.org",
    "https://evil.com?.example.org", "https://lists.example.org@evil.com/", "https://evil.com@lists.example.org/",
    "https://lists.example.org:pw@evil.com/", "https://lists.example.org./", "https://lists.example.org:99999999/",
    "http://lists.example.org/", "//evil.com", "///evil.com", "/\\evil.com", "\\\\evil.com", "javascript:alert(1)",
    "data:text/html,hi", "ftp://lists.example.org/", "https:///lists.example.org", "https://lists.example.org /x",
    "https://lists.example.org/\r\nSet-Cookie: a=b", "https://ｌｉｓｔｓ.example.org/", "evil.com", "lists.example.org", "",
    None, "https://lists.example.org/" + "a" * 3000,
])
def test_every_trick_to_leave_the_allowed_hosts_becomes_the_home_page(prod_hosts, evil):
    assert oidc_login.safe_next(evil) == "/"


def test_plain_http_is_only_accepted_locally(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_RETURN_HOSTS", ".example.org")
    monkeypatch.setattr(settings, "ENV", "local")
    assert oidc_login.safe_next("http://lists.example.org/") == "http://lists.example.org/"
    monkeypatch.setattr(settings, "ENV", "production")
    assert oidc_login.safe_next("http://lists.example.org/") == "/"


def test_with_nothing_configured_production_allows_no_other_host_at_all(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    assert oidc_login.safe_next("https://lists.example.org/") == "/"
    assert oidc_login.safe_next("/ok") == "/ok"


def test_locally_localhost_ports_are_allowed_by_default(monkeypatch):
    assert oidc_login.safe_next("http://localhost:8030/list.html") == "http://localhost:8030/list.html"
    assert oidc_login.safe_next("http://127.0.0.1:8060/") == "http://127.0.0.1:8060/"
    assert oidc_login.safe_next("http://evil.com:8030/") == "/"


def test_an_exact_host_pattern_matches_only_that_host(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "OIDC_RETURN_HOSTS", "lists.example.org, trips.example.org")
    assert oidc_login.safe_next("https://lists.example.org/") == "https://lists.example.org/"
    assert oidc_login.safe_next("https://x.lists.example.org/") == "/"
    assert oidc_login.safe_next("https://other.example.org/") == "/"


def test_the_bare_domain_is_not_a_subdomain(prod_hosts):
    assert oidc_login.safe_next("https://example.org/") == "/"


# --- the front door: full flow with a domain-wide cookie ------------------------------------


class Provider:
    def __init__(self, key):
        self.key = key
        self.nonce = None

    def get(self, url, **kw):
        return _Reply(200, {
            "authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/oauth/token",
            "end_session_endpoint": ISSUER + "/oidc/logout", "jwks_uri": ISSUER + "/keys",
        })

    def post(self, url, data=None, **kw):
        claims = {"iss": ISSUER + "/", "aud": CLIENT, "exp": int(time.time()) + 3600, "email": "alice@example.com",
                  "email_verified": True, "nonce": self.nonce}
        return _Reply(200, {"id_token": jwt.encode(claims, self.key, algorithm="RS256")})


class _Reply:
    def __init__(self, status, body):
        self.status_code, self.body = status, body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


@pytest.fixture()
def front(monkeypatch, key):
    """The dashboard: client id and secret, a domain-wide cookie, an allow-list of return hosts."""
    provider = Provider(key)
    monkeypatch.setattr(requests, "get", provider.get)
    monkeypatch.setattr(requests, "post", provider.post)
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", CLIENT)
    monkeypatch.setattr(settings, "OIDC_CLIENT_SECRET", "s3cret")
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", CLIENT)
    monkeypatch.setattr(settings, "OIDC_COOKIE_DOMAIN", ".example.org")
    monkeypatch.setattr(settings, "OIDC_RETURN_HOSTS", ".example.org")
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _t: key.public_key())
    client = TestClient(front_door, base_url="https://dashboard.example.org", follow_redirects=False)
    return client, provider


def sign_in(client, provider, next_):
    resp = client.get("/auth/login", params={"next": next_})
    query = {k: v[0] for k, v in parse_qs(urlparse(resp.headers["location"]).query).items()}
    provider.nonce = query["nonce"]
    return client.get("/auth/callback", params={"code": "c", "state": query["state"]})


def test_the_session_cookie_covers_the_whole_parent_domain_and_the_person_returns_to_their_app(front):
    client, provider = front
    resp = sign_in(client, provider, "https://lists.example.org/list.html?id=3")
    assert resp.headers["location"] == "https://lists.example.org/list.html?id=3"
    session = next(c for c in resp.headers.get_list("set-cookie") if c.startswith("oidc_session="))
    low = session.lower()
    assert "domain=.example.org" in low and "httponly" in low and "secure" in low and "samesite=lax" in low


def test_an_evil_return_address_still_signs_in_but_lands_on_the_front_door_home(front):
    client, provider = front
    assert sign_in(client, provider, "https://evil.example.com/steal").headers["location"] == "/"


def test_logout_clears_the_cookie_with_the_same_domain_so_it_is_really_gone(front):
    client, provider = front
    sign_in(client, provider, "/")
    resp = client.get("/auth/logout")
    gone = next(c for c in resp.headers.get_list("set-cookie") if c.startswith("oidc_session="))
    assert "max-age=0" in gone.lower() and "domain=.example.org" in gone.lower()


def test_without_a_cookie_domain_the_cookie_stays_on_the_host(front, monkeypatch):
    client, provider = front
    monkeypatch.setattr(settings, "OIDC_COOKIE_DOMAIN", None)
    session = next(c for c in sign_in(client, provider, "/").headers.get_list("set-cookie") if c.startswith("oidc_session="))
    assert "domain=" not in session.lower()


# --- every other app: verify-only ------------------------------------------------------------


@pytest.fixture()
def verify_only(monkeypatch, key):
    """An app: issuer, audience and the front door's address, but no client id or secret."""
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", CLIENT)
    monkeypatch.setattr(settings, "OIDC_LOGIN_URL", FRONT + "/auth/login")
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _t: key.public_key())
    return TestClient(app, base_url="https://lists.example.org", follow_redirects=False)


def test_a_verify_only_app_signs_people_in_from_the_shared_cookie(verify_only, key):
    verify_only.cookies.set("oidc_session", id_token(key, "bob@example.com"))
    assert verify_only.get("/who").json()["email"] == "bob@example.com"
    assert verify_only.get("/page").json() == {"page": "ok"}


def test_a_verify_only_app_has_no_sign_in_routes_of_its_own(verify_only):
    mine = FastAPI()
    mine.include_router(oidc_login.router)
    resp = TestClient(mine, base_url="https://lists.example.org", follow_redirects=False).get("/auth/login")
    assert resp.status_code == 404 and not oidc_login.enabled()


def test_a_signed_out_visitor_is_sent_to_the_front_door_with_the_full_address_to_come_back_to(verify_only):
    resp = verify_only.get("/page?x=1")
    assert resp.status_code == 302
    target = urlparse(resp.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == FRONT + "/auth/login"
    assert parse_qs(target.query)["next"] == ["https://lists.example.org/page?x=1"]


def test_the_address_to_come_back_to_would_pass_the_front_doors_own_check(verify_only, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_RETURN_HOSTS", ".example.org")
    target = urlparse(verify_only.get("/page?x=1").headers["location"])
    back = parse_qs(target.query)["next"][0]
    assert oidc_login.safe_next(back) == back


def test_an_expired_shared_cookie_is_sent_back_through_the_front_door(verify_only, key):
    verify_only.cookies.set("oidc_session", id_token(key, exp_in=-10))
    assert verify_only.get("/page").status_code == 302


def test_the_cookie_is_ignored_unless_an_issuer_is_configured(verify_only, key, monkeypatch):
    verify_only.cookies.set("oidc_session", id_token(key))
    monkeypatch.setattr(settings, "OIDC_ISSUER", None)
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", "t.cloudflareaccess.com")
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", "aud")
    assert verify_only.get("/who").status_code == 401


def test_the_front_door_never_redirects_to_itself(front):
    client, provider = front
    monkeypatch_login = settings.OIDC_LOGIN_URL
    settings.OIDC_LOGIN_URL = FRONT + "/auth/login"
    try:
        stub = FastAPI()

        @stub.get("/page")
        def home(request: Request):
            return oidc_login.redirect_if_signed_out(request, DEV) or {"page": "ok"}

        resp = TestClient(stub, base_url=FRONT, follow_redirects=False).get("/page")
        assert resp.status_code == 302 and resp.headers["location"].startswith("/auth/login?")  # its own flow, not a loop
    finally:
        settings.OIDC_LOGIN_URL = monkeypatch_login


def test_the_log_out_link_goes_to_the_front_doors_logout(verify_only):
    assert verify_only.get("/logout-url").json()["url"] == FRONT + "/auth/logout"


def test_the_log_out_link_is_cloudflares_for_cloudflare_visitors(verify_only):
    assert verify_only.get("/logout-url", headers={"Cf-Access-Jwt-Assertion": "x"}).json()["url"] is None


def test_the_log_out_link_is_the_apps_own_when_it_does_the_sign_in_itself(front):
    client, _ = front
    stub = FastAPI()

    @stub.get("/logout-url")
    def link(request: Request):
        return {"url": oidc_login.logout_url(request)}

    assert TestClient(stub).get("/logout-url").json()["url"] == "/auth/logout"


def test_the_log_out_link_has_no_override_when_nothing_is_configured():
    assert TestClient(app).get("/logout-url").json()["url"] is None


def test_locally_a_shared_cookie_wins_over_the_dev_user_and_a_bare_bearer_token_is_still_ignored(monkeypatch, key):
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", CLIENT)
    monkeypatch.setattr(settings, "OIDC_LOGIN_URL", "http://localhost:8090/auth/login")
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _t: key.public_key())
    local = TestClient(app, follow_redirects=False)
    assert local.get("/who").json()["email"] == DEV
    assert local.get("/who", headers={"Authorization": f"Bearer {id_token(key, 'mallory@example.com')}"}).json()["email"] == DEV
    local.cookies.set("oidc_session", id_token(key, "bob@example.com"))
    assert local.get("/who").json()["email"] == "bob@example.com"
    assert local.get("/page").json() == {"page": "ok"}  # locally nobody is bounced to a front door


def test_a_tampered_login_cookie_cannot_smuggle_in_an_evil_return_address(front):
    """The pending-login cookie is the browser's to edit (and a sibling subdomain can plant one), so the
    return address is checked again when it is used, not only when it was stored."""
    import base64
    import json

    client, provider = front
    provider.nonce = "n0nce"
    pending = {"state": "st4te", "nonce": "n0nce", "verifier": "v", "next": "https://evil.example.com/steal"}
    client.cookies.set("oidc_login", base64.urlsafe_b64encode(json.dumps(pending).encode()).decode().rstrip("="), path="/auth")
    resp = client.get("/auth/callback", params={"code": "c", "state": "st4te"})
    assert resp.status_code == 302 and resp.headers["location"] == "/"


def test_logout_comes_back_to_the_configured_page_on_the_front_doors_own_site(front, monkeypatch):
    client, provider = front
    monkeypatch.setattr(settings, "OIDC_LOGOUT_RETURN_PATH", "/signed-out")
    sign_in(client, provider, "/")
    target = urlparse(client.get("/auth/logout").headers["location"])
    assert parse_qs(target.query)["post_logout_redirect_uri"] == ["https://dashboard.example.org/signed-out"]


@pytest.mark.parametrize("evil", ["//evil.com", "https://evil.com/", "\\\\evil.com", "evil"])
def test_a_logout_return_path_cannot_point_anywhere_else(front, monkeypatch, evil):
    client, provider = front
    monkeypatch.setattr(settings, "OIDC_LOGOUT_RETURN_PATH", evil)
    target = urlparse(client.get("/auth/logout").headers["location"])
    assert parse_qs(target.query)["post_logout_redirect_uri"] == ["https://dashboard.example.org/"]


def test_locally_apps_on_other_ports_of_localhost_are_not_the_front_door(monkeypatch, key):
    """Every local app is localhost on its own port, so the front door check must look at the port too."""
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", CLIENT)
    monkeypatch.setattr(settings, "OIDC_LOGIN_URL", "http://localhost:8090/auth/login")
    other = TestClient(app, base_url="http://localhost:8030", follow_redirects=False)
    assert other.get("/logout-url").json()["url"] == "http://localhost:8090/auth/logout"
    door = TestClient(app, base_url="http://localhost:8090", follow_redirects=False)
    assert door.get("/logout-url").json()["url"] is None  # the front door itself: its own routes, or the default


@pytest.mark.parametrize("login,host,same", [
    ("https://dashboard.example.org/auth/login", "dashboard.example.org", True),
    ("https://dashboard.example.org/auth/login", "DASHBOARD.example.org:443", True),
    ("https://dashboard.example.org/auth/login", "lists.example.org", False),
    ("http://localhost:8090/auth/login", "localhost:8090", True),
    ("http://localhost:8090/auth/login", "localhost:8030", False),
])
def test_the_front_door_check_compares_host_and_port(login, host, same):
    class Req:
        headers = {"host": host}

        class url:
            scheme = "https" if login.startswith("https") else "http"
            netloc = host

    assert oidc_login._is_front_door_host(Req(), login) is same
