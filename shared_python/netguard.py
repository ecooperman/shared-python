"""Safe fetching of URLs that people type in.

The app fetches pages for URLs users supply (link previews, the stay
importer). Left unchecked, that lets any signed-in person point the server at
its own network: 127.0.0.1 (every other app on this machine listens there with
no login of its own), private ranges, or a cloud metadata address. So every
fetch goes through here:

- http/https only, and the host must resolve ONLY to public addresses
  (ipaddress's is_global: not loopback, private, link-local, CGNAT, multicast
  or reserved);
- redirects are followed by hand, each hop checked the same way - a public
  page can't bounce the request somewhere internal;
- the body is capped, so a huge or endless response can't tie the server up.

What this doesn't stop is DNS rebinding (a hostname that answers public to the
check and private to the connection a moment later). That needs an attacker
running their own DNS, which is outside what's worth guarding for an
invite-only app; if the app ever opens up properly, resolve once and connect to
that address instead.
"""
import ipaddress
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

MAX_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 5


class UnsafeURL(ValueError):
    """The address isn't one this server should fetch."""


def assert_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeURL("Only http(s) links can be fetched")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURL(f"Couldn't look up {parsed.hostname}") from exc
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise UnsafeURL(f"Couldn't look up {parsed.hostname}")
    for address in addresses:
        # A scoped IPv6 literal ("fe80::1%en0") is never public.
        ip = ipaddress.ip_address(address.split("%")[0])
        # is_global alone lets multicast through, so refuse that and reserved ranges too.
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise UnsafeURL("That address points inside a private network, so it can't be fetched")


def safe_get(url: str, headers: Optional[dict] = None, timeout: int = 10) -> requests.Response:
    """requests.get, minus the ability to reach non-public addresses. Raises
    UnsafeURL for a blocked address and requests.RequestException for ordinary
    network failures; the caller handles both."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        assert_public_url(current)
        response = requests.get(current, headers=headers, timeout=timeout, allow_redirects=False, stream=True)
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise requests.RequestException("Redirect with no Location")
            current = urljoin(current, location)
            continue
        body = response.raw.read(MAX_BYTES + 1, decode_content=True)
        response.close()
        if len(body) > MAX_BYTES:
            raise requests.RequestException("That page is too large to read")
        response._content = body  # what .text / .content / raise_for_status read from
        response._content_consumed = True
        return response
    raise requests.RequestException("Too many redirects")
