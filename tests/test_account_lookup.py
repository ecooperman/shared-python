"""Looking an address up at the sign-in provider, directly (the dashboard) or through the dashboard (every other app); a failure is just 'cannot tell'."""
import pytest
import requests

from shared_python import account_lookup, oidc_login, settings


class Reply:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body

    def json(self):
        if self._body == "not json":
            raise ValueError("no")
        return self._body


class Calls(list):
    state: dict = {}


@pytest.fixture()
def provider(monkeypatch):
    """The management settings are set (this is the dashboard); records what was asked of the provider."""
    calls = Calls()
    monkeypatch.setattr(settings, "AUTH0_MGMT_DOMAIN", "tenant.example.com")
    monkeypatch.setattr(settings, "AUTH0_MGMT_CLIENT_ID", "id")
    monkeypatch.setattr(settings, "AUTH0_MGMT_CLIENT_SECRET", "secret")
    monkeypatch.setattr(oidc_login, "_management_token", lambda: "TOKEN")
    state = {"reply": Reply(200, [])}

    def get(url, params=None, headers=None, timeout=None):
        calls.append({"url": url, "params": params, "headers": headers, "timeout": timeout})
        if isinstance(state["reply"], Exception):
            raise state["reply"]
        return state["reply"]

    monkeypatch.setattr(requests, "get", get)
    calls.state = state
    return calls


def test_an_address_with_no_account_is_false_and_one_with_an_account_is_true(provider):
    provider.state["reply"] = Reply(200, [])
    assert account_lookup.exists("Dana@Example.com") is False
    provider.state["reply"] = Reply(200, [{"user_id": "auth0|1"}])
    assert account_lookup.exists("dana@example.com") is True


def test_the_provider_is_asked_with_the_lowercased_address_and_the_management_token(provider):
    account_lookup.exists("  Dana@Example.com ")
    call = provider[0]
    assert call["url"] == "https://tenant.example.com/api/v2/users-by-email"
    assert call["params"] == {"email": "dana@example.com"} and call["headers"] == {"Authorization": "Bearer TOKEN"}


def test_anything_that_goes_wrong_is_cannot_tell_never_an_error(provider):
    for reply in (Reply(403, {"error": "insufficient_scope"}), Reply(429, {}), Reply(500, {}), Reply(200, "not json"), Reply(200, {"not": "a list"}),
                  requests.ConnectionError("down"), KeyError("access_token")):
        provider.state["reply"] = reply
        assert account_lookup.exists("dana@example.com") is None


def test_without_the_management_settings_or_a_dashboard_nothing_is_asked(monkeypatch):
    monkeypatch.setattr(settings, "AUTH0_MGMT_DOMAIN", None)
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", None)
    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("asked the provider"))
    monkeypatch.setattr(requests, "post", lambda *a, **k: pytest.fail("asked the dashboard"))
    assert account_lookup.exists("dana@example.com") is None
    assert account_lookup.exists("not an address") is None and account_lookup.exists("") is None


@pytest.fixture()
def via_dashboard(monkeypatch):
    calls = []
    monkeypatch.setattr(settings, "AUTH0_MGMT_DOMAIN", None)  # an app: no management credentials of its own
    monkeypatch.setattr(settings, "DASHBOARD_API_BASE", "http://127.0.0.1:8090/")
    state = {"reply": Reply(200, {"exists": True})}

    def post(url, json=None, timeout=None, allow_redirects=True):
        calls.append((url, json, timeout, allow_redirects))
        if isinstance(state["reply"], Exception):
            raise state["reply"]
        return state["reply"]

    monkeypatch.setattr(requests, "post", post)
    out = Calls()
    out.state = state
    out.calls = calls
    return out


def test_an_app_asks_the_dashboard_on_this_machine(via_dashboard):
    assert account_lookup.exists("dana@example.com") is True
    assert via_dashboard.calls == [("http://127.0.0.1:8090/internal/account-exists", {"email": "dana@example.com"}, 5, False)]
    via_dashboard.state["reply"] = Reply(200, {"exists": False})
    assert account_lookup.exists("dana@example.com") is False


def test_a_dashboard_that_cannot_tell_or_does_not_answer_is_cannot_tell(via_dashboard):
    for reply in (Reply(200, {"exists": None}), Reply(200, {}), Reply(404, {}), Reply(200, "not json"), requests.ConnectionError("down")):
        via_dashboard.state["reply"] = reply
        assert account_lookup.exists("dana@example.com") is None
