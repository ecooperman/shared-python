"""Cross-app request forgery. Every app lives on a subdomain of one parent domain and they share the sign-in cookie, so
a page on one app (or anywhere else) must not be able to make a visitor's browser change something in another.
These tests send the headers a browser would send and check what is refused: the point is that ONLY a request the
browser itself marks as coming from the app's own origin may change anything."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shared_python import csrf, settings

UNSAFE = ["POST", "PUT", "PATCH", "DELETE"]
SAFE = ["GET", "HEAD", "OPTIONS"]


def build():
    app = FastAPI()

    @app.api_route("/api/thing", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def thing():
        return {"ok": True}

    csrf.install(app)
    return app


@pytest.fixture()
def production(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    return TestClient(build(), base_url="https://finances.example.org", follow_redirects=False)


@pytest.fixture()
def local():
    return TestClient(build(), base_url="http://localhost:8080", follow_redirects=False)


def send(client, method, headers=None):
    return client.request(method, "/api/thing", headers=headers or {})


# --- a modern browser: Sec-Fetch-Site decides -------------------------------------------------------------------------


@pytest.mark.parametrize("method", UNSAFE)
def test_a_change_from_the_apps_own_page_is_allowed(production, method):
    assert send(production, method, {"Sec-Fetch-Site": "same-origin", "Origin": "https://finances.example.org"}).status_code == 200


@pytest.mark.parametrize("method", UNSAFE)
@pytest.mark.parametrize("site", ["same-site", "cross-site", "none", "", "SAME-SITE", "same-origin-x", "same_origin"])
def test_a_change_from_anywhere_else_is_refused_even_from_another_of_our_own_apps(production, method, site):
    headers = {"Sec-Fetch-Site": site, "Origin": "https://lists.example.org"}
    resp = send(production, method, headers)
    assert resp.status_code == 403 and "ok" not in resp.text


@pytest.mark.parametrize("method", UNSAFE)
def test_the_origin_header_cannot_override_what_the_browser_says_about_the_site(production, method):
    # A page on another app cannot claim to be this one: Sec-Fetch-Site is set by the browser, not by the page.
    headers = {"Sec-Fetch-Site": "same-site", "Origin": "https://finances.example.org"}
    assert send(production, method, headers).status_code == 403


@pytest.mark.parametrize("method", SAFE)
def test_reads_are_never_touched(production, method):
    resp = send(production, method, {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.com"})
    assert resp.status_code in (200, 405)  # not 403: the guard does not look at them


# --- an older browser: no Sec-Fetch-Site, so Origin decides ------------------------------------------------------------


@pytest.mark.parametrize("method", UNSAFE)
def test_without_fetch_metadata_the_apps_own_origin_is_allowed(production, method):
    assert send(production, method, {"Origin": "https://finances.example.org"}).status_code == 200


@pytest.mark.parametrize("method", UNSAFE)
@pytest.mark.parametrize("origin", [
    "https://lists.example.org", "https://evil.example.com", "null", "http://finances.example.org",
    "https://finances.example.org:8443", "https://finances.example.org.evil.com", "https://evil.com/finances.example.org",
    "https://xfinances.example.org", "",
])
def test_without_fetch_metadata_any_other_origin_is_refused(production, method, origin):
    assert send(production, method, {"Origin": origin}).status_code == 403


def test_the_origin_comparison_ignores_case_only(production):
    assert send(production, "POST", {"Origin": "HTTPS://Finances.Example.ORG"}).status_code == 200


# --- not a browser at all ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("method", UNSAFE)
def test_a_request_with_no_browser_headers_is_left_to_the_apps_own_checks(production, method):
    """Another app on this machine calling with a service token, curl, a test: no cookie is being abused."""
    assert send(production, method).status_code == 200


# --- production vs local ------------------------------------------------------------------------------------------------------


def test_in_production_the_apps_own_origin_is_https_whatever_the_proxy_shows(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    http_side = TestClient(build(), base_url="http://finances.example.org", follow_redirects=False)  # what the app sees behind Cloudflare
    assert send(http_side, "POST", {"Origin": "https://finances.example.org"}).status_code == 200
    assert send(http_side, "POST", {"Origin": "http://finances.example.org"}).status_code == 403  # a plain-http page is not us


def test_locally_the_apps_own_origin_includes_its_port(local):
    assert send(local, "POST", {"Origin": "http://localhost:8080"}).status_code == 200
    assert send(local, "POST", {"Origin": "http://localhost:8030"}).status_code == 403  # another local app
    assert send(local, "POST", {"Sec-Fetch-Site": "same-site", "Origin": "http://localhost:8030"}).status_code == 403


# --- explicitly trusted origins (an installed extension) ----------------------------------------------------------------------


def test_nothing_is_trusted_unless_it_is_listed(production):
    headers = {"Sec-Fetch-Site": "none", "Origin": "chrome-extension://abcdef"}
    assert send(production, "POST", headers).status_code == 403


def test_a_listed_origin_may_make_changes_whatever_the_fetch_metadata_says(production, monkeypatch):
    monkeypatch.setattr(settings, "CSRF_TRUSTED_ORIGINS", "chrome-extension://abcdef, https://other.example.org")
    for site in ("none", "cross-site", "same-site"):
        assert send(production, "POST", {"Sec-Fetch-Site": site, "Origin": "chrome-extension://abcdef"}).status_code == 200


def test_listing_one_origin_does_not_trust_another_or_a_lookalike(production, monkeypatch):
    monkeypatch.setattr(settings, "CSRF_TRUSTED_ORIGINS", "chrome-extension://abcdef")
    for origin in ("chrome-extension://abcdefg", "chrome-extension://abcde", "chrome-extension://ABCDEF.evil", "https://evil.example.com"):
        assert send(production, "POST", {"Sec-Fetch-Site": "cross-site", "Origin": origin}).status_code == 403


def test_a_listed_origin_has_to_be_sent_as_the_origin_not_guessed_from_another_header(production, monkeypatch):
    monkeypatch.setattr(settings, "CSRF_TRUSTED_ORIGINS", "https://trusted.example.org")
    headers = {"Sec-Fetch-Site": "cross-site", "Referer": "https://trusted.example.org/"}
    assert send(production, "POST", headers).status_code == 403


# --- what a refusal looks like and what it never reveals --------------------------------------------------------------------------


def test_a_refusal_says_what_happened_without_echoing_anything_and_is_not_cached(production):
    resp = send(production, "POST", {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.com/<script>"})
    assert resp.status_code == 403 and resp.headers["cache-control"] == "no-store"
    assert "evil" not in resp.text and "<script>" not in resp.text


def test_a_refusal_is_logged_with_the_origin_but_never_the_cookie(production, caplog):
    with caplog.at_level("WARNING"):
        send(production, "POST", {"Sec-Fetch-Site": "same-site", "Cookie": "oidc_session=SECRET-TOKEN-VALUE", "Origin": "https://lists.example.org"})
    assert "same-site" in caplog.text and "/api/thing" in caplog.text
    assert "SECRET-TOKEN-VALUE" not in caplog.text and "oidc_session" not in caplog.text


def test_the_log_line_names_both_headers_so_a_legitimate_client_can_be_listed(production, caplog):
    with caplog.at_level("WARNING"):
        send(production, "POST", {"Sec-Fetch-Site": "none", "Origin": "chrome-extension://abcdef", "Cookie": "oidc_session=SECRET"})
    assert "Sec-Fetch-Site='none'" in caplog.text and "chrome-extension://abcdef" in caplog.text and "SECRET" not in caplog.text
