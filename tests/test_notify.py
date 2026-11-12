"""Telling the administrator something is waiting. Each channel is stubbed at
the network edge so these check exactly what would be sent - and that one
channel failing never stops the rest."""
import logging
import smtplib

import pytest
import requests

from shared_python import notify
from shared_python import settings as config


class Ok:
    def raise_for_status(self):
        pass


@pytest.fixture()
def posts(monkeypatch):
    sent = []

    def fake(url, json=None, data=None, headers=None, timeout=None):
        sent.append({"url": url, "json": json, "data": data, "headers": headers, "timeout": timeout})
        return Ok()

    monkeypatch.setattr(requests, "post", fake)
    return sent


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.log = host, port, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        self.log.append("starttls")

    def login(self, user, password):
        self.log.append(("login", user, password))

    def send_message(self, msg):
        self.log.append(("send", msg))


@pytest.fixture()
def smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", type("FakeSSL", (FakeSMTP,), {}))
    return FakeSMTP


def test_with_nothing_configured_nothing_is_sent(posts, smtp):
    notify.notify("Title", "Body", "https://x.example/page")
    assert posts == [] and smtp.instances == []


def test_ntfy_posts_the_message_to_the_topic_with_a_link(posts, monkeypatch):
    monkeypatch.setattr(config, "NTFY_TOPIC", "my-long-random-topic")
    notify.notify("Title", "Body", "https://x.example/page")
    (call,) = posts
    assert call["url"] == "https://ntfy.sh"
    assert call["json"] == {"topic": "my-long-random-topic", "title": "Title", "message": "Body", "click": "https://x.example/page"}
    assert call["headers"] == {} and call["timeout"]


def test_ntfy_can_use_another_server_and_a_token(posts, monkeypatch):
    monkeypatch.setattr(config, "NTFY_TOPIC", "t")
    monkeypatch.setattr(config, "NTFY_SERVER", "https://ntfy.example.com")
    monkeypatch.setattr(config, "NTFY_TOKEN", "tk_abc")
    notify.notify("Title", "Body")
    (call,) = posts
    assert call["url"] == "https://ntfy.example.com"
    assert call["headers"] == {"Authorization": "Bearer tk_abc"}
    assert "click" not in call["json"]


def test_pushover_needs_both_its_keys(posts, monkeypatch):
    monkeypatch.setattr(config, "PUSHOVER_APP_TOKEN", "app-token")
    notify.notify("Title", "Body")
    assert posts == []

    monkeypatch.setattr(config, "PUSHOVER_USER_KEY", "user-key")
    notify.notify("Title", "Body", "https://x.example/page")
    (call,) = posts
    assert call["url"] == "https://api.pushover.net/1/messages.json"
    assert call["data"] == {"token": "app-token", "user": "user-key", "title": "Title", "message": "Body", "url": "https://x.example/page"}


def test_email_uses_starttls_and_logs_in(smtp, monkeypatch):
    for name, value in dict(SMTP_HOST="smtp.example.com", SMTP_PORT=587, SMTP_USERNAME="user", SMTP_PASSWORD="pw",
                            SMTP_FROM="lists@example.com", NOTIFY_EMAIL="me@example.com").items():
        monkeypatch.setattr(config, name, value)
    notify.notify("Title", "Body", "https://x.example/page")

    (server,) = smtp.instances
    assert (server.host, server.port) == ("smtp.example.com", 587)
    assert server.log[:2] == ["starttls", ("login", "user", "pw")]
    msg = server.log[2][1]
    assert (msg["Subject"], msg["From"], msg["To"]) == ("Title", "lists@example.com", "me@example.com")
    assert "Body" in msg.get_content() and "https://x.example/page" in msg.get_content()


def test_port_465_is_ssl_from_the_start(smtp, monkeypatch):
    for name, value in dict(SMTP_HOST="smtp.example.com", SMTP_PORT=465, SMTP_FROM="a@example.com", NOTIFY_EMAIL="b@example.com").items():
        monkeypatch.setattr(config, name, value)
    notify.notify("Title", "Body")
    (server,) = smtp.instances
    assert type(server).__name__ == "FakeSSL"
    assert "starttls" not in server.log  # and no login: no username set
    assert [entry[0] for entry in server.log] == ["send"]


def test_email_needs_a_host_a_sender_and_a_recipient(smtp, monkeypatch):
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "SMTP_FROM", "a@example.com")
    notify.notify("Title", "Body")  # no NOTIFY_EMAIL
    assert smtp.instances == []


def test_a_broken_channel_doesnt_stop_the_others_or_leak_its_secrets(posts, smtp, monkeypatch, caplog):
    monkeypatch.setattr(config, "NTFY_TOPIC", "t")
    monkeypatch.setattr(config, "PUSHOVER_APP_TOKEN", "app-token-secret")
    monkeypatch.setattr(config, "PUSHOVER_USER_KEY", "user-key-secret")
    for name, value in dict(SMTP_HOST="smtp.example.com", SMTP_FROM="a@example.com", NOTIFY_EMAIL="b@example.com").items():
        monkeypatch.setattr(config, name, value)

    def fake(url, json=None, data=None, headers=None, timeout=None):
        if url == "https://ntfy.sh":
            raise requests.ConnectionError("could not reach https://ntfy.sh/t")
        if data and data.get("token") == "app-token-secret":
            raise requests.HTTPError("400 for token app-token-secret")
        return Ok()

    monkeypatch.setattr(requests, "post", fake)
    with caplog.at_level(logging.DEBUG):
        notify.notify("Title", "Body")  # must not raise

    assert len(smtp.instances) == 1  # email still went out after both push channels failed
    assert "ntfy" in caplog.text and "pushover" in caplog.text
    assert "app-token-secret" not in caplog.text and "ntfy.sh/t" not in caplog.text


# --- email to a person (not the administrator) ---------------------------------


def _configure_smtp(monkeypatch, port=587):
    for name, value in (("SMTP_HOST", "smtp.example.com"), ("SMTP_PORT", port), ("SMTP_USERNAME", "u"), ("SMTP_PASSWORD", "p"), ("SMTP_FROM", "Lists <lists@example.com>")):
        monkeypatch.setattr(config, name, value)


def test_send_email_without_a_server_does_nothing(smtp):
    assert notify.send_email("x@example.com", "hi", "body") is False
    assert smtp.instances == []


def test_send_email_goes_to_the_given_person_not_the_administrator(smtp, monkeypatch):
    _configure_smtp(monkeypatch)
    monkeypatch.setattr(config, "NOTIFY_EMAIL", "admin@example.com")
    assert notify.send_email("friend@example.com", "Subject", "Body") is True
    msg = smtp.instances[0].log[-1][1]
    assert msg["To"] == "friend@example.com" and msg["From"] == "Lists <lists@example.com>"


def test_the_subject_is_one_line_even_if_a_list_name_is_not(smtp, monkeypatch):
    _configure_smtp(monkeypatch)
    notify.send_email("a@example.com", 'shared "Line one\nBcc: evil@example.com"', "body")
    msg = smtp.instances[0].log[-1][1]
    assert "\n" not in msg["Subject"] and msg["Bcc"] is None


def test_an_email_can_carry_a_rich_version_and_a_reply_to(smtp, monkeypatch):
    _configure_smtp(monkeypatch)
    assert notify.send_email("a@example.com", "Hi", "plain words", html="<p>rich <b>words</b></p>", reply_to="sender@example.com") is True
    msg = smtp.instances[0].log[-1][1]
    assert msg["Reply-To"] == "sender@example.com"
    assert msg.get_body(("plain",)).get_content().strip() == "plain words"
    assert "<b>words</b>" in msg.get_body(("html",)).get_content()


def test_a_plain_email_has_no_rich_part_and_no_reply_to(smtp, monkeypatch):
    _configure_smtp(monkeypatch)
    notify.send_email("a@example.com", "Hi", "plain words")
    msg = smtp.instances[0].log[-1][1]
    assert msg["Reply-To"] is None and msg.get_body(("html",)) is None


def test_a_reply_to_cannot_start_a_new_header(smtp, monkeypatch):
    _configure_smtp(monkeypatch)
    notify.send_email("a@example.com", "Hi", "body", reply_to="x@example.com\nBcc: evil@example.com")
    msg = smtp.instances[0].log[-1][1]
    assert "\n" not in msg["Reply-To"] and msg["Bcc"] is None


def test_tell_given_access_does_nothing_without_a_server_and_never_raises(smtp):
    notify.tell_given_access("a@example.com", "b@example.com", "list", "Gifts", "https://x.example/list.html?id=1", "view", True, "Lists")
    assert smtp.instances == []


def test_an_smtp_refusal_is_logged_with_the_servers_reason_but_other_errors_stay_type_only(monkeypatch, caplog):
    _configure_smtp(monkeypatch)

    class Refusing:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            pass

        def login(self, user, password):
            pass

        def send_message(self, msg):
            raise smtplib.SMTPDataError(550, b"The evancooperman.com domain is not verified.")

    monkeypatch.setattr(smtplib, "SMTP", Refusing)
    with caplog.at_level("WARNING"):
        notify.tell_given_access("a@example.com", "b@example.com", "list", "Gifts", "https://x.example/list.html?id=1", "view", False, "Lists")
    assert "SMTPDataError 550 The evancooperman.com domain is not verified." in caplog.text

    # Anything that isn't an SMTP reply still logs only its type: its message could carry a secret.
    caplog.clear()
    assert notify.describe_failure(OSError("connect to smtp.example.com as user=u password=hunter2")) == "OSError"


# --- the wording is the app's to choose ------------------------------------------


def test_the_email_to_a_new_person_names_what_was_shared_where_and_how_to_sign_in(smtp, monkeypatch):
    _configure_smtp(monkeypatch)
    notify.tell_given_access("dana@example.com", "alice@example.com", "trip", "Lisbon", "https://trips.example/trip.html?id=7", "edit", True, "Trip Planning")
    msg = smtp.instances[0].log[-1][1]
    body = msg.get_content()
    assert msg["To"] == "dana@example.com" and 'shared "Lisbon" with you' in msg["Subject"]
    assert 'gave you access to the trip "Lisbon" in Trip Planning - you can edit it.' in body
    assert "Open it here: https://trips.example/trip.html?id=7" in body
    assert "\n    dana@example.com\n" in body and "one-time PIN" in body


def test_someone_who_has_signed_in_before_is_not_told_how(smtp, monkeypatch):
    _configure_smtp(monkeypatch)
    notify.tell_given_access("dana@example.com", "alice@example.com", "list", "Gifts", None, "view", False, "Lists")
    body = smtp.instances[0].log[-1][1].get_content()
    assert "one-time PIN" not in body and "Open it here" not in body  # no link given, none shown


def test_the_administrator_alert_uses_the_apps_name_and_link(posts, monkeypatch):
    monkeypatch.setattr(config, "NTFY_TOPIC", "t")
    notify.invite_requested("Trips", "alice@example.com", "new@example.com", "edit", "https://trips.example/invites.html")
    sent = posts[0]["json"]
    assert sent["title"] == "Trips: invite waiting for approval"
    assert "alice@example.com wants to let new@example.com in (can edit)" in sent["message"]
    assert sent["click"] == "https://trips.example/invites.html"


# --- an invite to the app itself (no list or trip to name) ------------------------


def test_the_administrator_alert_for_an_app_invite_has_no_access_level(posts, monkeypatch):
    monkeypatch.setattr(config, "NTFY_TOPIC", "t")
    notify.invite_requested("Notes", "alice@example.com", "new@example.com", None, "https://notes.example/invites.html")
    message = posts[0]["json"]["message"]
    assert message == "alice@example.com wants to let new@example.com in."


def test_the_email_to_someone_let_into_the_app_says_how_to_sign_in(smtp, monkeypatch):
    _configure_smtp(monkeypatch)
    notify.tell_let_in("dana@example.com", "alice@example.com", "Notes", "https://notes.example")
    msg = smtp.instances[0].log[-1][1]
    body = msg.get_content()
    assert msg["To"] == "dana@example.com" and msg["Subject"] == "alice@example.com invited you to Notes"
    assert "invited you to Notes, and an administrator has approved it." in body
    assert "Open it here: https://notes.example" in body
    assert "\n    dana@example.com\n" in body and "one-time PIN" in body


def test_telling_someone_they_were_let_in_does_nothing_without_a_server_and_never_raises(smtp):
    notify.tell_let_in("a@example.com", "b@example.com", "Notes", None)
    assert smtp.instances == []
