"""A library imported through lazy_module loads on first use, not at import time."""
import sys

from shared_python.lazy import lazy_module


def test_nothing_is_imported_until_an_attribute_is_used():
    sys.modules.pop("colorsys", None)
    proxy = lazy_module("colorsys")
    assert "colorsys" not in sys.modules  # making the proxy imports nothing
    assert proxy.rgb_to_hsv(1, 1, 1) == (0, 0, 1)  # the first use loads the real module
    assert "colorsys" in sys.modules


def test_a_test_can_replace_an_attribute_and_put_it_back(monkeypatch):
    proxy = lazy_module("colorsys")
    monkeypatch.setattr(proxy, "rgb_to_hsv", lambda *a: "fake")
    assert proxy.rgb_to_hsv(0, 0, 0) == "fake"
    monkeypatch.undo()
    assert proxy.rgb_to_hsv(0, 0, 0) == (0, 0, 0)


def test_a_missing_attribute_is_still_an_attribute_error():
    import pytest

    with pytest.raises(AttributeError):
        lazy_module("colorsys").no_such_thing
