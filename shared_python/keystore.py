"""Encrypting people's own API keys for storage.

Apps that call paid services (Anthropic, Google Maps, ...) let each person bring
their own key instead of metering strangers on the owner's bill. This is the part
that is the same everywhere: checking that something looks like a key, encrypting
it (Fernet, keyed from KEY_ENCRYPTION_SECRET), and reading it back. Which providers
exist, how a key is checked with its service, and the table it lives in stay with
each app (see trip-planning's app/apikeys.py, or the scaffold's api-keys module).

Saved keys must never be sent back to a browser (keep only `last4` in the clear)
and never be logged. Honest limits: this protects a copy of the database file (a
backup, a download for inspection); it can't protect against someone who has taken
over the running server, which holds the secret too.
"""
import base64
import hashlib
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from . import settings

log = logging.getLogger(__name__)

MIN_LENGTH = 16
MAX_LENGTH = 400

# Used only when no secret is set and we're not in production.
_DEV_SECRET = "local-development-only-not-a-secret"


class KeyStorageNotConfigured(Exception):
    """Production, and KEY_ENCRYPTION_SECRET isn't set."""


def storage_available() -> bool:
    return bool(settings.KEY_ENCRYPTION_SECRET) or settings.ENV != "production"


def _fernet() -> Fernet:
    secret = settings.KEY_ENCRYPTION_SECRET
    if not secret:
        if settings.ENV == "production":
            raise KeyStorageNotConfigured()
        secret = _DEV_SECRET
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


def clean(raw: str) -> str:
    """The key, trimmed, or ValueError if it can't be one (so a paste slip is
    caught before any service is called)."""
    key = (raw or "").strip()
    if not (MIN_LENGTH <= len(key) <= MAX_LENGTH) or any(c.isspace() or ord(c) < 33 for c in key):
        raise ValueError("That doesn't look like an API key - paste the whole key, with no spaces")
    return key


def last4(key: str) -> str:
    return key[-4:]


def encrypt(key: str) -> str:
    """The text to store in the database. Raises KeyStorageNotConfigured."""
    return _fernet().encrypt(key.encode()).decode()


def decrypt(token: str, label: str = "saved") -> Optional[str]:
    """The key, or None if it can't be read (the secret changed, or the server has
    none). Logged without anything from the key; `label` names it (e.g. the provider)."""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, KeyStorageNotConfigured):
        log.warning("A saved %s key could not be decrypted (was KEY_ENCRYPTION_SECRET changed?)", label)
        return None


def scrub(text: str, key: str) -> str:
    """A service's message made safe to show: the key removed, whitespace tidied,
    and cut short."""
    return " ".join((text or "").replace(key, "...").split())[:200]
