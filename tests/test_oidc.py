"""Signing in with a hosted identity provider's token (any OIDC issuer). Written
against a tiny app of its own, the way a real app uses request_email(). The point
of these tests: the provider is only settings, and the ways a token can be wrong
(issuer, audience, expiry, signature, algorithm tricks, no or unverified email)
are all refused."""
import time

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from shared_python import auth, settings

ISSUER = "https://login.example.com"
AUD = "my-app"
DEV = "dev@localhost.test"

app = FastAPI()


@app.get("/who")
def who(request: Request):
    return {"email": auth.request_email(request, DEV)}


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def rsa_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


@pytest.fixture(scope="module")
def ec_key():
    private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key()


def make(private, email="alice@example.com", alg="RS256", iss=ISSUER, aud=AUD, exp_in=300, claim="email", **extra):
    claims = {"iss": iss, "exp": int(time.time()) + exp_in, **extra}
    if email is not None:
        claims[claim] = email
    if aud is not None:
        claims["aud"] = aud
    return jwt.encode(claims, private, algorithm=alg)


@pytest.fixture()
def production(monkeypatch, rsa_key):
    """Production with only a provider configured (no Cloudflare)."""
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", AUD)
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _token: rsa_key[1])


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# --- the happy path, however the provider delivers the token ----------------------


def test_a_bearer_token_identifies_the_person(client, production, rsa_key):
    resp = client.get("/who", headers=bearer(make(rsa_key[0], "Alice@Example.com")))
    assert resp.status_code == 200 and resp.json()["email"] == "Alice@Example.com"  # the app normalizes case


def test_the_providers_session_cookie_works_when_its_name_is_set(client, production, rsa_key, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_COOKIE", "__session")
    client.cookies.set("__session", make(rsa_key[0]))
    resp = client.get("/who")
    assert resp.status_code == 200 and resp.json()["email"] == "alice@example.com"


def test_a_cookie_is_ignored_unless_its_name_is_configured(client, production, rsa_key):
    client.cookies.set("__session", make(rsa_key[0]))
    assert client.get("/who").status_code == 401


def test_an_elliptic_curve_provider_works_when_its_algorithm_is_allowed(client, production, ec_key, monkeypatch):
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _token: ec_key[1])
    monkeypatch.setattr(settings, "OIDC_ALGORITHMS", "RS256,ES256")
    assert client.get("/who", headers=bearer(make(ec_key[0], alg="ES256"))).status_code == 200


def test_the_issuer_may_be_configured_with_or_without_a_trailing_slash(client, production, rsa_key, monkeypatch):
    for configured in (ISSUER + "/", ISSUER):
        monkeypatch.setattr(settings, "OIDC_ISSUER", configured)
        for iss in (ISSUER, ISSUER + "/"):  # Auth0 puts a slash in its tokens, others do not
            assert client.get("/who", headers=bearer(make(rsa_key[0], iss=iss))).status_code == 200


def test_several_audiences_may_be_configured_and_the_token_may_carry_a_list(client, production, rsa_key, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", "something-else, my-app")
    assert client.get("/who", headers=bearer(make(rsa_key[0]))).status_code == 200
    assert client.get("/who", headers=bearer(make(rsa_key[0], aud=["x", "my-app"]))).status_code == 200


def test_a_provider_whose_tokens_have_no_audience_works_when_none_is_configured(client, production, rsa_key, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", None)
    assert client.get("/who", headers=bearer(make(rsa_key[0], aud=None))).status_code == 200


def test_the_email_claim_name_is_a_setting(client, production, rsa_key, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_EMAIL_CLAIM", "https://example.com/email")
    token = make(rsa_key[0], claim="https://example.com/email")
    assert client.get("/who", headers=bearer(token)).json()["email"] == "alice@example.com"


# --- everything wrong with a token ------------------------------------------------


def test_a_wrong_issuer_is_rejected(client, production, rsa_key):
    assert client.get("/who", headers=bearer(make(rsa_key[0], iss="https://evil.example.com"))).status_code == 401


def test_a_wrong_audience_is_rejected(client, production, rsa_key):
    assert client.get("/who", headers=bearer(make(rsa_key[0], aud="another-app"))).status_code == 401


def test_a_token_with_no_audience_is_rejected_when_one_is_required(client, production, rsa_key):
    assert client.get("/who", headers=bearer(make(rsa_key[0], aud=None))).status_code == 401


def test_an_expired_token_is_rejected(client, production, rsa_key):
    assert client.get("/who", headers=bearer(make(rsa_key[0], exp_in=-10))).status_code == 401


def test_a_token_signed_by_another_key_is_rejected(client, production):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert client.get("/who", headers=bearer(make(other))).status_code == 401


def test_garbage_is_rejected(client, production):
    assert client.get("/who", headers=bearer("not-a-token")).status_code == 401


def test_a_symmetric_token_signed_with_the_public_key_is_rejected(client, production, rsa_key):
    # The classic algorithm-confusion forgery: HS256 using the public key as the secret.
    # PyJWT refuses to build this itself, so it is forged by hand, as an attacker would.
    import base64
    import hashlib
    import hmac
    import json

    from cryptography.hazmat.primitives import serialization

    def b64(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    public_pem = rsa_key[1].public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = {"iss": ISSUER, "aud": AUD, "email": "alice@example.com", "exp": int(time.time()) + 300}
    body = b64(json.dumps(claims).encode())
    signature = b64(hmac.new(public_pem, header + b"." + body, hashlib.sha256).digest())
    forged = (header + b"." + body + b"." + signature).decode()
    assert client.get("/who", headers=bearer(forged)).status_code == 401


def test_an_unsigned_token_is_rejected(client, production):
    claims = {"iss": ISSUER, "aud": AUD, "email": "alice@example.com", "exp": int(time.time()) + 300}
    unsigned = jwt.encode(claims, None, algorithm="none")
    assert client.get("/who", headers=bearer(unsigned)).status_code == 401


def test_symmetric_algorithms_are_never_allowed_even_if_configured(client, production, rsa_key, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ALGORITHMS", "HS256,none")
    resp = client.get("/who", headers=bearer(make(rsa_key[0])))
    assert resp.status_code == 503  # misconfigured: refused, not silently weakened


def test_a_token_with_no_email_is_rejected_and_the_log_says_which_claim_to_add(client, production, rsa_key, caplog):
    with caplog.at_level("WARNING"):
        resp = client.get("/who", headers=bearer(make(rsa_key[0], email=None, sub="user_123")))
    assert resp.status_code == 401 and "no email" in resp.json()["detail"]
    assert "'email' claim" in caplog.text and "OIDC_EMAIL_CLAIM" in caplog.text


def test_an_unverified_email_is_rejected(client, production, rsa_key):
    assert client.get("/who", headers=bearer(make(rsa_key[0], email_verified=False))).status_code == 401
    assert client.get("/who", headers=bearer(make(rsa_key[0], email_verified="false"))).status_code == 401
    assert client.get("/who", headers=bearer(make(rsa_key[0], email_verified=True))).status_code == 200
    assert client.get("/who", headers=bearer(make(rsa_key[0]))).status_code == 200  # a provider that omits it is trusted to verify


def test_no_token_means_not_signed_in(client, production):
    assert client.get("/who").status_code == 401


def test_the_plain_cloudflare_email_header_is_never_trusted_in_production(client, production):
    assert client.get("/who", headers={"Cf-Access-Authenticated-User-Email": "alice@example.com"}).status_code == 401


# --- finding the provider's keys --------------------------------------------------


@pytest.fixture()
def real_keys(monkeypatch):
    """Use the real key lookup, with the network stubbed: records what was fetched."""
    monkeypatch.setattr(auth, "_oidc_client", None)
    fetched = []

    class Reply:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self.body

    def get(url, **kw):
        fetched.append(url)
        return Reply({"jwks_uri": "https://login.example.com/keys.json"})

    monkeypatch.setattr(requests, "get", get)
    seen = []
    monkeypatch.setattr(jwt, "PyJWKClient", lambda url, **kw: seen.append(url) or object())
    return fetched, seen


def test_keys_are_found_through_the_issuers_discovery_document(monkeypatch, real_keys):
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER + "/")
    monkeypatch.setattr(settings, "OIDC_JWKS_URL", None)
    try:
        auth._oidc_signing_key("token")
    except AttributeError:
        pass  # the stand-in client has no get_signing_key_from_jwt; only the lookup matters
    fetched, seen = real_keys
    assert fetched == ["https://login.example.com/.well-known/openid-configuration"]
    assert seen == ["https://login.example.com/keys.json"]


def test_an_explicit_keys_url_skips_discovery(monkeypatch, real_keys):
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_JWKS_URL", "https://keys.example.com/jwks")
    try:
        auth._oidc_signing_key("token")
    except AttributeError:
        pass
    fetched, seen = real_keys
    assert fetched == [] and seen == ["https://keys.example.com/jwks"]


def test_a_provider_that_cant_be_reached_is_a_401_not_a_crash(client, production, rsa_key, monkeypatch, caplog):
    def down(token):
        raise requests.ConnectionError("HTTPSConnectionPool(host='login.example.com'): secret-in-url")

    monkeypatch.setattr(auth, "_oidc_signing_key", down)
    with caplog.at_level("WARNING"):
        resp = client.get("/who", headers=bearer(make(rsa_key[0])))
    assert resp.status_code == 401
    assert "ConnectionError" in caplog.text and "secret-in-url" not in caplog.text  # the type only


# --- alongside Cloudflare ----------------------------------------------------------


@pytest.fixture()
def both(production, monkeypatch, rsa_key):
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", "team.cloudflareaccess.com")
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", "cf-aud")
    monkeypatch.setattr(auth, "_signing_key", lambda _token: rsa_key[1])


def cf_token(private, email="cf@example.com"):
    return jwt.encode({"email": email, "aud": ["cf-aud"], "exp": int(time.time()) + 300}, private, algorithm="RS256")


def test_either_kind_of_token_signs_you_in_when_both_are_configured(client, both, rsa_key):
    assert client.get("/who", headers={"Cf-Access-Jwt-Assertion": cf_token(rsa_key[0])}).json()["email"] == "cf@example.com"
    assert client.get("/who", headers=bearer(make(rsa_key[0]))).json()["email"] == "alice@example.com"


def test_a_cloudflare_token_wins_and_a_bad_one_is_not_rescued_by_a_provider_token(client, both, rsa_key):
    good = {"Cf-Access-Jwt-Assertion": cf_token(rsa_key[0])}
    assert client.get("/who", headers={**good, **bearer(make(rsa_key[0], "other@example.com"))}).json()["email"] == "cf@example.com"
    bad = {"Cf-Access-Jwt-Assertion": "garbage"}
    assert client.get("/who", headers={**bad, **bearer(make(rsa_key[0]))}).status_code == 401


def test_cloudflare_alone_still_ignores_provider_tokens(client, monkeypatch, rsa_key):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "CF_TEAM_DOMAIN", "team.cloudflareaccess.com")
    monkeypatch.setattr(settings, "CF_ACCESS_AUD", "cf-aud")
    assert client.get("/who", headers=bearer(make(rsa_key[0]))).status_code == 401


def test_a_cloudflare_header_is_ignored_when_only_a_provider_is_configured(client, production, rsa_key):
    resp = client.get("/who", headers={"Cf-Access-Jwt-Assertion": "garbage", **bearer(make(rsa_key[0]))})
    assert resp.status_code == 200 and resp.json()["email"] == "alice@example.com"


def test_with_neither_configured_production_refuses_everything(client, monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    assert client.get("/who").status_code == 503
    assert client.get("/who", headers={"Cf-Access-Authenticated-User-Email": "alice@example.com"}).status_code == 503


def test_locally_the_provider_is_not_consulted_at_all(client, monkeypatch, rsa_key):
    monkeypatch.setattr(settings, "ENV", "local")
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _token: pytest.fail("no provider calls in local development"))
    assert client.get("/who", headers=bearer(make(rsa_key[0]))).json()["email"] == DEV
