"""The paid services a person can bring their own key for, and a tiny real check of a key before it is saved.

The keys themselves are kept once per person on the dashboard (dashboard/app/keys.py) and fetched by the apps that need one
(shared_python.user_keys). What the services are called, what they are for and how to check a key is the same everywhere, so it lives here.

`verify` makes one tiny real call per provider so a typo (or a Google key without the Distance Matrix API turned on) is caught while the person
is still on the page. It returns (True, "") if the provider accepted the key, (False, why) if it refused it, or (None, why) if we could not
tell (the service was unreachable), in which case the key is saved anyway and the person is told it was not checked."""
import logging
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import requests

from .keystore import scrub

log = logging.getLogger(__name__)

TIMEOUT = 10


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    feature: str  # shown to the person: "<feature> needs your own <label> key"
    description: str
    optional: bool  # the feature works without it, just less well
    get_url: str  # where to create a key


PROVIDERS: Dict[str, Provider] = {
    "anthropic": Provider(
        id="anthropic",
        label="Anthropic",
        feature="AI features in Trips and Jobs",
        description="Used by Trips to read a lodging listing (or a screenshot of one) and fill in the price, rooms and amenities, and by Jobs to draft a resume, review it and score jobs against it.",
        optional=False,
        get_url="https://console.anthropic.com/settings/keys",
    ),
    "google_maps": Provider(
        id="google_maps",
        label="Google Maps",
        feature="Distances and travel times in Trips",
        description="Looks up real walking and driving distances between your activities and stays in Trips. The key needs the Distance Matrix API turned on.",
        optional=False,
        get_url="https://console.cloud.google.com/apis/credentials",
    ),
    "jina": Provider(
        id="jina",
        label="Jina Reader",
        feature="Reading hard-to-fetch pages in Trips",
        description="Optional. Helps Trips read listing pages that block normal fetching, so more of them import cleanly.",
        optional=True,
        get_url="https://jina.ai/reader/",
    ),
}


def _verify_anthropic(key: str) -> Tuple[Optional[bool], str]:
    r = requests.get(
        "https://api.anthropic.com/v1/models",
        params={"limit": 1},
        headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
        timeout=TIMEOUT,
    )
    if r.status_code in (401, 403):
        return False, "Anthropic didn't accept that key"
    if r.ok:
        return True, ""
    return None, f"Anthropic answered with an error ({r.status_code})"


def _verify_google(key: str) -> Tuple[Optional[bool], str]:
    r = requests.get(
        "https://maps.googleapis.com/maps/api/distancematrix/json",
        params={"origins": "Boston, MA", "destinations": "Cambridge, MA", "mode": "walking", "key": key},
        timeout=TIMEOUT,
    )
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    result = data.get("status")
    if result == "OK":
        return True, ""
    if result in ("REQUEST_DENIED", "INVALID_REQUEST"):
        return False, "Google refused that key: " + scrub(data.get("error_message") or result, key)
    if result == "OVER_QUERY_LIMIT":
        return True, ""  # a real key that is simply out of quota right now
    return None, f"Google answered with an unexpected status ({result or r.status_code})"


def _verify_jina(key: str) -> Tuple[Optional[bool], str]:
    r = requests.get("https://r.jina.ai/https://example.com", headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT)
    if r.status_code in (401, 403):
        return False, "Jina didn't accept that key"
    if r.ok:
        return True, ""
    return None, f"Jina answered with an error ({r.status_code})"


_VERIFIERS = {"anthropic": _verify_anthropic, "google_maps": _verify_google, "jina": _verify_jina}


def verify(provider: str, key: str) -> Tuple[Optional[bool], str]:
    try:
        return _VERIFIERS[provider](key)
    except (requests.RequestException, ValueError) as exc:
        # The type only: a library's message can echo the URL, and a URL can carry the key.
        log.warning("Checking a %s key failed: %s", provider, type(exc).__name__)
        return None, f"Couldn't reach {PROVIDERS[provider].label} to check the key"
