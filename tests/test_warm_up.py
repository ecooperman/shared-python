"""After a restart, the first sign-in check used to wait for two web calls to the identity provider (its discovery document, then
its signing keys), in every app. Now each app fetches the keys in the background as it starts and refreshes them before they
expire, so nobody's first page waits for them, and failing to fetch is never fatal."""
import json
import threading
from contextlib import asynccontextmanager

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shared_python import accounts_gate, auth, owner_gate, settings

ISSUER = "https://login.example.com"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setattr(auth, "_oidc_client", None)
    monkeypatch.setattr(auth, "_jwks_client", None)
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", None)
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", None)
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_JWKS_URL", f"{ISSUER}/keys")  # one explicit address: no discovery call


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def provider(monkeypatch, key):
    """A provider whose keys we can count fetches of (PyJWKClient's own download is what is replaced)."""
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    fetched = []

    def fetch_data(self):
        fetched.append(self.uri)
        return {"keys": [jwk]}

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fetch_data)
    return fetched


def token(key):
    return jwt.encode({"iss": ISSUER, "sub": "x"}, key, algorithm="RS256", headers={"kid": "k1"})


def test_warming_up_fetches_the_keys_so_the_first_sign_in_check_makes_no_web_call(provider, key):
    auth.warm_up()
    assert provider == [f"{ISSUER}/keys"]
    assert auth._oidc_signing_key(token(key)) is not None
    assert provider == [f"{ISSUER}/keys"]  # still just the one fetch: the check used what was already there


def test_without_warming_up_the_first_check_does_the_fetch(provider, key):
    auth._oidc_signing_key(token(key))
    assert provider == [f"{ISSUER}/keys"]


def test_refreshing_fetches_again_and_a_plain_warm_up_does_not(provider):
    auth.warm_up()
    auth.warm_up()
    assert len(provider) == 1
    auth.warm_up(refresh=True)
    assert len(provider) == 2


def test_each_configured_provider_is_warmed(provider, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ISSUER", f"{ISSUER}, https://other.example.com")
    monkeypatch.setattr(settings, "OIDC_JWKS_URL", None)
    monkeypatch.setattr(auth, "_oidc_jwks_url", lambda issuer: f"{issuer}/keys")
    auth.warm_up()
    assert sorted(provider) == [f"{ISSUER}/keys", "https://other.example.com/keys"]


def test_cloudflares_keys_are_warmed_too(provider, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ISSUER", None)
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", "https://team.cloudflareaccess.com/")
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", "aud")
    auth.warm_up()
    assert provider == ["https://team.cloudflareaccess.com/cdn-cgi/access/certs"]


def test_with_nothing_configured_it_does_nothing(provider, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ISSUER", None)
    auth.warm_up()
    assert provider == []


def test_a_provider_that_cannot_be_reached_is_logged_never_raised(monkeypatch, caplog):
    def down(self):
        raise ConnectionError("provider down")

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", down)
    auth.warm_up()  # must not raise
    assert "Could not pre-fetch the sign-in keys" in caplog.text and "provider down" not in caplog.text  # type only: a library's message can echo a URL


def test_the_first_real_request_still_works_when_warming_failed(monkeypatch, key):
    calls = []

    def flaky(self):
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionError("down")
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", flaky)
    auth.warm_up()  # fails quietly
    assert auth._oidc_signing_key(token(key)) is not None  # the request does what it always did


def test_it_starts_in_the_background_when_the_app_starts_and_not_before(monkeypatch):
    started = []

    class FakeThread:
        def __init__(self, target, name, daemon):
            self.target, self.name, self.daemon = target, name, daemon

        def start(self):
            started.append(self)

    monkeypatch.setattr(threading, "Thread", FakeThread)
    app = FastAPI()
    auth.warm_up_on_start(app)
    assert started == []  # building the app costs nothing
    with TestClient(app):  # entering runs the app's start-up
        assert len(started) == 1 and started[0].daemon is True and started[0].target is auth._keep_warm


def test_an_apps_own_start_up_and_shut_down_code_still_runs(monkeypatch):
    monkeypatch.setattr(threading, "Thread", lambda **kw: type("T", (), {"start": lambda self: None})())
    events = []

    @asynccontextmanager
    async def theirs(app):
        events.append("up")
        yield {"db": "ready"}
        events.append("down")

    app = FastAPI(lifespan=theirs)
    auth.warm_up_on_start(app)
    with TestClient(app):
        assert events == ["up"]
    assert events == ["up", "down"]


def test_the_keys_are_refreshed_before_they_expire(monkeypatch):
    calls = []
    monkeypatch.setattr(auth, "warm_up", lambda refresh=False: calls.append(refresh))

    def sleep(seconds):
        calls.append(("sleep", seconds))
        if len([c for c in calls if isinstance(c, tuple)]) == 2:
            raise SystemExit

    monkeypatch.setattr(auth.time, "sleep", sleep)
    with pytest.raises(SystemExit):
        auth._keep_warm()
    assert calls == [False, ("sleep", 3000), True, ("sleep", 3000)]
    assert auth.WARM_EVERY_SECONDS < 3600  # strictly inside the hour the keys are cached for


@pytest.mark.parametrize("install", ["accounts", "owner"])
def test_both_gates_start_it(monkeypatch, install):
    seen = []
    monkeypatch.setattr(auth, "warm_up_on_start", lambda app: seen.append(app))
    app = FastAPI()
    if install == "accounts":
        accounts_gate.install(app, account_for=lambda e: "none", dev_user_email="dev@x.test")
    else:
        owner_gate.install(app, admin_emails=lambda: [], dev_user_email="dev@x.test")
    assert seen == [app]
