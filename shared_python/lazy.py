"""Import a heavy library only when it is first used.

The `anthropic` library takes more than half a second to import, and four apps import it at the top of a module even though most
page loads never call the AI. Importing it at start-up made every restart (every deploy) and every first page load slower.
Write `anthropic = lazy_module("anthropic")` where `import anthropic` used to be; everything else (`anthropic.Anthropic(...)`,
`except anthropic.APIConnectionError`) reads the same, and the real import happens on the first attribute used.

Two things to know: a type annotation that names the module (`-> anthropic.Anthropic`) is evaluated when the function is defined,
which would load it right away, so quote it (`-> "anthropic.Anthropic"`); and a test may still replace an attribute
(`monkeypatch.setattr(mod.anthropic, "Anthropic", Fake)`): what is set on the proxy wins over the real module's.
"""
import importlib


class LazyModule:
    def __init__(self, name: str):
        object.__setattr__(self, "_lazy_name", name)
        object.__setattr__(self, "_lazy_module", None)

    def _load(self):
        module = object.__getattribute__(self, "_lazy_module")
        if module is None:
            module = importlib.import_module(object.__getattribute__(self, "_lazy_name"))
            object.__setattr__(self, "_lazy_module", module)
        return module

    def __getattr__(self, attr: str):  # only reached when the proxy itself has no such attribute
        return getattr(self._load(), attr)

    def __repr__(self) -> str:
        return f"<lazy module {object.__getattribute__(self, '_lazy_name')!r}>"


def lazy_module(name: str) -> LazyModule:
    return LazyModule(name)
