"""Whatever is set in the developer's shell (a real Cloudflare token, a real ntfy
topic), a test must never reach out with it: the settings are blanked, and any
HTTP or SMTP call a test didn't stub fails loudly."""
import logging
import smtplib

import pytest
import requests

from shared_python import settings


@pytest.fixture(autouse=True)
def _nothing_leaves_the_machine(monkeypatch):
    for name in (
        "CF_API_TOKEN", "CF_ACCOUNT_ID", "CF_INVITEES_GROUP_ID", "NTFY_TOPIC", "NTFY_TOKEN",
        "PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY", "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD",
        "SMTP_FROM", "NOTIFY_EMAIL", "CF_TEAM_DOMAIN", "CF_ACCESS_AUD",
    ):
        monkeypatch.setattr(settings, name, None)
    monkeypatch.setattr(settings, "ENV", "local")
    monkeypatch.setattr(settings, "ACCESS_SEAT_CAP", 50)

    def refuse(*args, **kwargs):
        raise AssertionError(f"a test made a real network call: {args[:2]}")

    monkeypatch.setattr(requests, "request", refuse)
    monkeypatch.setattr(requests, "post", refuse)
    monkeypatch.setattr(smtplib, "SMTP", refuse)
    monkeypatch.setattr(smtplib, "SMTP_SSL", refuse)
    for name in logging.root.manager.loggerDict:
        logging.getLogger(name).disabled = False
