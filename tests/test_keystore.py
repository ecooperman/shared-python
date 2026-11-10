"""Encrypting, reading back and cleaning up people's own API keys."""
import logging

import pytest

from shared_python import keystore, settings

KEY = "sk-ant-alice-0123456789abcdef"


@pytest.fixture()
def secret(monkeypatch):
    monkeypatch.setattr(settings, "KEY_ENCRYPTION_SECRET", "the-original-secret-long-enough")


def test_a_key_round_trips_and_the_stored_text_hides_it(secret):
    token = keystore.encrypt(KEY)
    assert KEY not in token and KEY[-8:] not in token
    assert keystore.decrypt(token) == KEY


def test_encrypting_twice_gives_different_text_that_both_read_back(secret):
    first, second = keystore.encrypt(KEY), keystore.encrypt(KEY)
    assert first != second and keystore.decrypt(first) == keystore.decrypt(second) == KEY


def test_locally_with_no_secret_a_development_one_is_used(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "local")
    assert keystore.storage_available() is True
    assert keystore.decrypt(keystore.encrypt(KEY)) == KEY


def test_in_production_a_secret_is_needed_to_save(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    assert keystore.storage_available() is False
    with pytest.raises(keystore.KeyStorageNotConfigured):
        keystore.encrypt(KEY)
    monkeypatch.setattr(settings, "KEY_ENCRYPTION_SECRET", "now-it-is-set-long-enough")
    assert keystore.storage_available() is True


def test_a_key_saved_under_another_secret_is_unreadable_and_not_leaked(secret, monkeypatch, caplog):
    token = keystore.encrypt(KEY)
    monkeypatch.setattr(settings, "KEY_ENCRYPTION_SECRET", "a-different-secret-entirely-now")
    with caplog.at_level(logging.WARNING):
        assert keystore.decrypt(token, "anthropic") is None
    assert "anthropic key could not be decrypted" in caplog.text
    assert KEY not in caplog.text and token not in caplog.text


def test_without_the_secret_in_production_a_saved_key_is_unreadable_not_a_crash(secret, monkeypatch):
    token = keystore.encrypt(KEY)
    monkeypatch.setattr(settings, "KEY_ENCRYPTION_SECRET", None)
    monkeypatch.setattr(settings, "ENV", "production")
    assert keystore.decrypt(token) is None


def test_garbage_is_unreadable_not_a_crash(secret):
    assert keystore.decrypt("not-a-token") is None


def test_clean_trims_and_accepts_a_whole_key():
    assert keystore.clean(f"  {KEY}\n") == KEY


@pytest.mark.parametrize("bad", [None, "", "short", "has a space in the middle of it", "x" * 401, "tab\tinside-a-long-enough-key"])
def test_clean_refuses_anything_that_cant_be_a_key(bad):
    with pytest.raises(ValueError):
        keystore.clean(bad)


def test_last4_is_all_that_is_kept_in_the_clear():
    assert keystore.last4(KEY) == "cdef"


def test_a_services_message_is_shown_without_the_key_and_kept_short():
    text = f"Not authorized.\n  key={KEY}   " + "word " * 100
    shown = keystore.scrub(text, KEY)
    assert KEY not in shown and "\n" not in shown and len(shown) <= 200 and shown.startswith("Not authorized. key=...")
    assert keystore.scrub(None, KEY) == ""
