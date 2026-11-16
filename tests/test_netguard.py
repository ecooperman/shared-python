"""A server that fetches pages for URLs people type in must never be steerable at its own network: every other app
on this machine listens on 127.0.0.1 with no login of its own, and cloud metadata addresses hold credentials. The
guard refuses anything that is not a public address, checks every redirect hop, and caps the body."""
import socket

import pytest
import requests

from shared_python import netguard
from shared_python.netguard import UnsafeURL, assert_public_url


def resolve_to(monkeypatch, *addresses):
    def fake(host, port, **kwargs):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", fake)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.9.9", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::5", "224.0.0.1"],
)
def test_non_public_addresses_are_refused(monkeypatch, address):
    resolve_to(monkeypatch, address)
    with pytest.raises(UnsafeURL):
        assert_public_url("https://example.com/page")


def test_a_host_that_resolves_to_any_private_address_is_refused(monkeypatch):
    resolve_to(monkeypatch, "93.184.216.34", "127.0.0.1")  # one good answer doesn't excuse a bad one
    with pytest.raises(UnsafeURL):
        assert_public_url("https://example.com/")


def test_public_addresses_and_only_http_schemes_pass(monkeypatch):
    resolve_to(monkeypatch, "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
    assert_public_url("https://example.com/")
    for url in ("file:///etc/passwd", "ftp://example.com/", "gopher://example.com/", "javascript:alert(1)", "http:///nohost"):
        with pytest.raises(UnsafeURL):
            assert_public_url(url)


def test_literal_internal_urls_are_refused_without_any_dns(monkeypatch):
    for url in ("http://127.0.0.1:8030/api/lists", "http://localhost:8080/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/"):
        with pytest.raises(UnsafeURL):
            assert_public_url(url)


class FakeResponse:
    def __init__(self, status=200, location=None, body=b"<html></html>"):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.is_redirect = bool(location)
        self.is_permanent_redirect = False
        self._body = body
        self.raw = self
        self.closed = False

    @property
    def content(self):
        return self._content

    def read(self, n, decode_content=False):
        return self._body[:n]

    def close(self):
        self.closed = True


def test_a_redirect_to_an_internal_address_is_blocked(monkeypatch):
    def fake_dns(host, port, **kwargs):
        address = "127.0.0.1" if host == "internal.example" else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    fetched = []

    def fake_get(url, **kwargs):
        fetched.append(url)
        assert kwargs["allow_redirects"] is False  # redirects are followed by hand, so each hop is checked
        return FakeResponse(302, location="http://internal.example/secret") if "public.example" in url else FakeResponse()

    monkeypatch.setattr(netguard.socket, "getaddrinfo", fake_dns)
    monkeypatch.setattr(netguard.requests, "get", fake_get)
    with pytest.raises(UnsafeURL):
        netguard.safe_get("https://public.example/start")
    assert fetched == ["https://public.example/start"]  # the internal hop was never requested


def test_redirects_are_followed_and_capped(monkeypatch):
    resolve_to(monkeypatch, "93.184.216.34")
    hops = iter(range(100))
    monkeypatch.setattr(netguard.requests, "get", lambda url, **kw: FakeResponse(302, location=f"https://example.com/{next(hops)}"))
    with pytest.raises(requests.RequestException, match="Too many redirects"):
        netguard.safe_get("https://example.com/")

    resolve_to(monkeypatch, "93.184.216.34")
    answers = iter([FakeResponse(301, location="/next"), FakeResponse(body=b"final")])
    monkeypatch.setattr(netguard.requests, "get", lambda url, **kw: next(answers))
    assert netguard.safe_get("https://example.com/start").content == b"final"


def test_an_oversized_body_is_refused(monkeypatch):
    resolve_to(monkeypatch, "93.184.216.34")
    monkeypatch.setattr(netguard, "MAX_BYTES", 10)
    monkeypatch.setattr(netguard.requests, "get", lambda url, **kw: FakeResponse(body=b"x" * 50))
    with pytest.raises(requests.RequestException, match="too large"):
        netguard.safe_get("https://example.com/")


def test_an_ipv4_address_wrapped_in_ipv6_is_still_internal(monkeypatch):
    resolve_to(monkeypatch, "::ffff:127.0.0.1")
    with pytest.raises(UnsafeURL):
        assert_public_url("https://example.com/")


@pytest.mark.parametrize("url", ["http://2130706433/", "http://0x7f000001/", "http://017700000001/", "http://127.1/", "http://0/"])
def test_odd_spellings_of_loopback_are_refused_because_the_resolved_address_is_what_counts(monkeypatch, url):
    resolve_to(monkeypatch, "127.0.0.1")  # what the resolver makes of any of these spellings
    with pytest.raises(UnsafeURL):
        assert_public_url(url)


def test_a_url_with_credentials_or_odd_ports_is_judged_by_its_real_host(monkeypatch):
    resolve_to(monkeypatch, "127.0.0.1")
    for url in ("http://example.com@127.0.0.1/", "http://user:pw@localhost:8080/"):
        with pytest.raises(UnsafeURL):
            assert_public_url(url)


def test_a_failed_lookup_is_refused_not_ignored(monkeypatch):
    def broken(host, port, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(netguard.socket, "getaddrinfo", broken)
    with pytest.raises(UnsafeURL):
        assert_public_url("https://does-not-exist.example/")
