"""How an app learns who is asking: the dev fallback locally, and in production
the Cloudflare Access token (verified). Written against a tiny app of its own,
the way a real app uses request_email()."""
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from shared_python import auth, settings

AUD = "test-aud-tag"
DEV = "dev@localhost.test"

app = FastAPI()


@app.get("/who")
def who(request: Request):
    return {"email": auth.request_email(request, DEV)}


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def token(private, email="alice@example.com", aud=AUD, exp_in=300, **extra):
    claims = {"email": email, "aud": [aud], "exp": int(time.time()) + exp_in, **extra}
    return jwt.encode(claims, private, algorithm="RS256")


@pytest.fixture()
def production(monkeypatch, keypair):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", "team.cloudflareaccess.com")
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", AUD)
    monkeypatch.setattr(auth, "_signing_key", lambda _token: keypair[1])


def test_locally_with_no_header_you_are_the_dev_user(client):
    assert client.get("/who").json()["email"] == DEV


def test_locally_a_header_or_cookie_plays_someone_else(client):
    assert client.get("/who", headers={"Cf-Access-Authenticated-User-Email": "bob@example.com"}).json()["email"] == "bob@example.com"
    assert client.get("/who", cookies={"dev_user": "carol@example.com"}).json()["email"] == "carol@example.com"


def test_a_valid_token_identifies_the_person(client, production, keypair):
    resp = client.get("/who", headers={"Cf-Access-Jwt-Assertion": token(keypair[0], "Alice@Example.com")})
    assert resp.status_code == 200 and resp.json()["email"] == "Alice@Example.com"  # the app normalizes case


@pytest.mark.parametrize(
    "build",
    [
        lambda private: token(private, aud="some-other-app"),
        lambda private: token(private, exp_in=-10),
        lambda private: token(private, email=None),
        lambda private: jwt.encode({"email": "alice@example.com", "aud": [AUD], "exp": int(time.time()) + 300}, "not-the-key", algorithm="HS256"),
        lambda private: "garbage",
    ],
    ids=["wrong audience", "expired", "no email", "wrong signature", "not a token"],
)
def test_a_bad_token_is_rejected(client, production, keypair, build):
    assert client.get("/who", headers={"Cf-Access-Jwt-Assertion": build(keypair[0])}).status_code == 401


def test_any_of_several_configured_audiences_is_accepted(client, production, keypair, monkeypatch):
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", f"some-other-app, {AUD}")
    assert client.get("/who", headers={"Cf-Access-Jwt-Assertion": token(keypair[0])}).status_code == 200
    assert client.get("/who", headers={"Cf-Access-Jwt-Assertion": token(keypair[0], aud="neither")}).status_code == 401


def test_a_forged_plain_header_is_ignored_when_tokens_are_verified(client, production):
    assert client.get("/who", headers={"Cf-Access-Authenticated-User-Email": "alice@example.com"}).status_code == 401


def test_no_identity_at_all_is_a_401_in_production(client, production):
    assert client.get("/who").status_code == 401


def test_without_token_config_production_refuses_everything_even_with_the_header(client, monkeypatch):
    # A hostname that bypasses Access lets anyone send this header themselves.
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", None)
    assert client.get("/who").status_code == 503
    assert client.get("/who", headers={"Cf-Access-Authenticated-User-Email": "alice@example.com"}).status_code == 503


@pytest.mark.parametrize("pasted", ["team.cloudflareaccess.com", "https://team.cloudflareaccess.com/", " team.cloudflareaccess.com "])
def test_the_team_domain_may_be_pasted_with_a_scheme_or_slash(monkeypatch, pasted):
    seen = []
    monkeypatch.setattr(auth, "_jwks_client", None)
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", pasted)
    monkeypatch.setattr(auth.jwt, "PyJWKClient", lambda url, **kw: seen.append(url) or object())
    try:
        auth._signing_key("token")
    except AttributeError:
        pass  # the stand-in client has no get_signing_key_from_jwt; only the URL matters
    assert seen == ["https://team.cloudflareaccess.com/cdn-cgi/access/certs"]
    monkeypatch.setattr(auth, "_jwks_client", None)
