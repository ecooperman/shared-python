"""The call that lets an email through Cloudflare's login gate. Cloudflare is
stubbed at the HTTP layer, so these check exactly what we send and how every
kind of answer is handled."""
import logging

import pytest
import requests

from shared_python import cloudflare
from shared_python import settings as config

TOKEN = "secret-token-value"
GROUP_URL = "https://api.cloudflare.com/client/v4/accounts/acct123/access/groups/group456"


class Reply:
    def __init__(self, result=None, status=200, errors=None):
        self.status_code = status
        self.ok = status < 400
        self._body = {"success": self.ok and not errors, "result": result, "errors": errors or []}

    def json(self):
        return self._body


def rule(email):
    return {"email": {"email": email}}


@pytest.fixture()
def configured(monkeypatch):
    monkeypatch.setattr(config, "CF_API_TOKEN", TOKEN)
    monkeypatch.setattr(config, "CF_ACCOUNT_ID", "acct123")
    monkeypatch.setattr(config, "CF_INVITEES_GROUP_ID", "group456")


@pytest.fixture()
def group(configured, monkeypatch):
    """A fake Cloudflare holding one Access group; `calls` records each request."""
    state = {
        "calls": [],
        "group": {
            "name": "Invitees",
            "include": [rule("old@example.com"), {"everyone": {}}],
            "exclude": [rule("banned@example.com")],
            "require": [{"geo": {"country_code": "US"}}],
        },
    }

    def fake(method, url, headers=None, json=None, timeout=None, **kw):
        state["calls"].append((method, url, headers, json, timeout))
        if method == "get":
            return Reply(dict(state["group"]))
        state["group"] = {"name": json["name"], "include": json["include"], "exclude": json["exclude"], "require": json["require"]}
        return Reply(dict(state["group"]))

    monkeypatch.setattr(requests, "request", fake)
    return state


def test_the_email_is_added_and_everything_else_in_the_group_is_kept(group):
    cloudflare.allow_email("new@example.com")

    (get, put) = group["calls"]
    assert (get[0], get[1]) == ("get", GROUP_URL)
    assert (put[0], put[1]) == ("put", GROUP_URL)
    assert put[2] == {"Authorization": f"Bearer {TOKEN}"}
    assert put[4] is not None  # never waits forever on Cloudflare
    # The update replaces the whole group, so nothing already there may be lost.
    assert put[3] == {
        "name": "Invitees",
        "include": [rule("old@example.com"), {"everyone": {}}, rule("new@example.com")],
        "exclude": [rule("banned@example.com")],
        "require": [{"geo": {"country_code": "US"}}],
    }


def test_an_email_already_in_the_group_changes_nothing(group):
    cloudflare.allow_email("old@example.com")
    assert [c[0] for c in group["calls"]] == ["get"]


def test_the_group_is_matched_ignoring_case(group):
    group["group"]["include"] = [rule("Old@Example.com")]
    cloudflare.allow_email("old@example.com")
    assert [c[0] for c in group["calls"]] == ["get"]


def test_a_full_group_is_refused_before_anything_is_written(group, monkeypatch):
    monkeypatch.setattr(config, "ACCESS_SEAT_CAP", 1)  # old@example.com already fills it
    with pytest.raises(cloudflare.SeatCapReached) as exc:
        cloudflare.allow_email("new@example.com")
    assert "1" in str(exc.value)
    assert [c[0] for c in group["calls"]] == ["get"]


def test_only_email_rules_count_toward_the_cap(group, monkeypatch):
    # The group holds one email and one non-email rule; a cap of 2 leaves room.
    monkeypatch.setattr(config, "ACCESS_SEAT_CAP", 2)
    cloudflare.allow_email("new@example.com")
    assert [c[0] for c in group["calls"]] == ["get", "put"]


def test_cloudflare_refusing_is_reported_with_its_reason_but_not_our_token(configured, monkeypatch, caplog):
    monkeypatch.setattr(
        requests, "request", lambda *a, **kw: Reply(status=403, errors=[{"code": 10000, "message": "Authentication error"}])
    )
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(cloudflare.CloudflareError) as exc:
            cloudflare.allow_email("new@example.com")
    assert "Authentication error" in str(exc.value)
    assert "Authentication error" in caplog.text  # it was logged, so the check below means something
    assert TOKEN not in str(exc.value) and TOKEN not in caplog.text


def test_an_unreachable_cloudflare_is_reported_without_internals(configured, monkeypatch, caplog):
    def down(*a, **kw):
        raise requests.ConnectionError(f"HTTPSConnectionPool(host='api.cloudflare.com'): {TOKEN}")

    monkeypatch.setattr(requests, "request", down)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(cloudflare.CloudflareError) as exc:
            cloudflare.allow_email("new@example.com")
    assert "try again" in str(exc.value)
    assert "ConnectionError" in caplog.text  # it was logged, so the check below means something
    assert TOKEN not in str(exc.value) and TOKEN not in caplog.text


def test_a_reply_that_isnt_json_is_an_error_not_a_crash(configured, monkeypatch):
    class Garbage:
        status_code, ok = 502, False

        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(requests, "request", lambda *a, **kw: Garbage())
    with pytest.raises(cloudflare.CloudflareError):
        cloudflare.allow_email("new@example.com")


def test_an_update_that_doesnt_stick_is_an_error(group, monkeypatch):
    real = requests.request

    def forgetful(method, url, **kw):
        reply = real(method, url, **kw)
        if method == "put":
            return Reply({"name": "Invitees", "include": [rule("old@example.com")]})  # our email is missing
        return reply

    monkeypatch.setattr(requests, "request", forgetful)
    with pytest.raises(cloudflare.CloudflareError):
        cloudflare.allow_email("new@example.com")


def test_unconfigured_it_does_nothing_locally(monkeypatch):
    monkeypatch.setattr(config, "ENV", "local")
    cloudflare.allow_email("new@example.com")  # the autouse guard fails the test on any HTTP call


def test_unconfigured_in_production_it_refuses(monkeypatch):
    monkeypatch.setattr(config, "ENV", "production")
    with pytest.raises(cloudflare.NotConfigured):
        cloudflare.allow_email("new@example.com")


@pytest.mark.parametrize("missing", ["CF_API_TOKEN", "CF_ACCOUNT_ID", "CF_INVITEES_GROUP_ID"])
def test_all_three_settings_are_needed(configured, monkeypatch, missing):
    monkeypatch.setattr(config, missing, None)
    monkeypatch.setattr(config, "ENV", "production")
    with pytest.raises(cloudflare.NotConfigured):
        cloudflare.allow_email("new@example.com")


# --- asking whether an email is let in --------------------------------------------


def test_unconfigured_there_is_nothing_to_ask(monkeypatch):
    assert cloudflare.is_let_in("anyone@example.com", set()) is None  # and the autouse guard fails any HTTP call


def test_membership_of_the_group_decides(group):
    assert cloudflare.is_let_in("old@example.com", set()) is True
    group["group"]["include"] = [rule("Mixed@Example.com")]  # Cloudflare keeps whatever case it was given
    assert cloudflare.is_let_in("mixed@example.com", set()) is True
    assert cloudflare.is_let_in("stranger@example.com", set()) is False
    assert {c[0] for c in group["calls"]} == {"get"}  # only ever reads


def test_an_administrator_is_always_let_in(group):
    assert cloudflare.is_let_in("boss@example.com", {"boss@example.com"}) is True
    assert group["calls"] == []  # they get in by their own policy, not the group


def test_a_group_we_cant_read_is_an_error_not_a_no(configured, monkeypatch):
    monkeypatch.setattr(
        requests, "request", lambda *a, **kw: Reply(status=403, errors=[{"code": 10000, "message": "Authentication error"}])
    )
    with pytest.raises(cloudflare.CloudflareError):
        cloudflare.is_let_in("old@example.com", set())
