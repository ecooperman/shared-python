"""What every page of every app shares, kept in ONE place.

1. THE HEAD (`templates/shared_head.html`): the character set, the viewport, the shared theme stylesheet, the favicons and `theme-init.js`
(which sets light/dark before the first paint). An app's Jinja templates include it:

    templates = Jinja2Templates(directory="templates")
    pages.install(templates)            # once, where `templates` is made

    <head>
      {% include "shared_head.html" %}
      <title>Lists</title>
      ...the page's own lines...
    </head>

The include reads `shared_assets_base` from the page's context, as every page already passes it. A page that is not a Jinja template (the
sign-in error page in `oidc_login`) uses `head_html(base)` for the same lines. The icons are tags in the HTML itself (not added later by
JavaScript), so they show from the first paint, in link previews and with scripts off.

2. VERSIONED FILE ADDRESSES. `install` also gives templates two functions, so a page names its scripts and styles like this:

    <script src="{{ shared_asset('theme.js') }}"></script>    -> https://static.../theme.js?v=3f9a1c07be
    <script src="{{ asset('list.js') }}"></script>            -> /list.js?v=51d0c2aa90   (the app's own static folder)

`v` is a short hash of the file's contents, so the address changes exactly when the file does. A file whose address carries `v` can be kept by the
browser for a year (see `install_cache_headers`), and a changed file simply has a new address - no stale copies, no waiting on a revalidation
round trip per file. A file that cannot be found gets its plain address (which stays `no-store`), so a missing folder never breaks a page.

3. CACHE HEADERS (`install_cache_headers(app)`): the ONE place that decides Cache-Control for an app. Everything is `no-store` as before (a page, a
JSON answer, an iOS home-screen app must never show stale data) EXCEPT a script, stylesheet or image requested with `?v=`, which is
`public, max-age=31536000, immutable`. It replaces the near-identical `no_cache` middleware each app used to carry."""
import hashlib
import os
from pathlib import Path
from urllib.parse import parse_qs


TEMPLATES_DIR = Path(__file__).parent / "templates"

# Where the shared-assets files are on this machine, to hash them. Every app and shared-assets sit side by side (`/opt/apps/<repo>` on the
# droplet, the same folder locally), and an app runs from its own folder, so the sibling is found with no setting; SHARED_ASSETS_DIR overrides it.
SHARED_ASSETS_DIR = Path(os.environ.get("SHARED_ASSETS_DIR") or Path("..") / "shared-assets" / "static")

# What `install_cache_headers` lets the browser keep (only when requested with ?v=).
STATIC_EXTENSIONS = (".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2")
IMMUTABLE = "public, max-age=31536000, immutable"
NO_STORE = "no-store"

_hashes: dict = {}  # path -> ((mtime_ns, size), short hash): a file is re-read only when it changes


def file_version(path) -> "str | None":
    """A short hash of the file's contents, or None if it cannot be read."""
    path = Path(path)
    try:
        stat = path.stat()
        key = (stat.st_mtime_ns, stat.st_size)
        cached = _hashes.get(path)
        if cached and cached[0] == key:
            return cached[1]
        digest = hashlib.sha1(path.read_bytes()).hexdigest()[:10]
    except OSError:
        return None
    _hashes[path] = (key, digest)
    return digest


def versioned(base: str, directory, name: str) -> str:
    """`<base>/<name>?v=<hash of the file in directory>`, or without `?v` when the file is not there."""
    name = name.lstrip("/")
    version = file_version(Path(directory) / name)
    return f"{base}/{name}" + (f"?v={version}" if version else "")


def _shared_asset_function():
    from jinja2 import pass_context

    @pass_context
    def shared_asset(context, name: str) -> str:
        return versioned(context.get("shared_assets_base", ""), SHARED_ASSETS_DIR, name)

    return shared_asset


def install(templates, static_dir="static") -> None:
    """Let this app's templates `{% include "shared_head.html" %}` and use `asset(...)` / `shared_asset(...)`. `templates` is a starlette
    `Jinja2Templates`; the app's own folder is searched first. `static_dir` is the folder the app serves its own scripts and styles from."""
    from jinja2 import ChoiceLoader, FileSystemLoader

    templates.env.loader = ChoiceLoader([templates.env.loader, FileSystemLoader(str(TEMPLATES_DIR))])
    templates.env.globals["shared_asset"] = _shared_asset_function()
    templates.env.globals["asset"] = lambda name: versioned("", static_dir, name)


def head_html(shared_assets_base: str) -> str:
    """The same lines as a string, for a page built in Python."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=select_autoescape(["html"]))
    env.globals["shared_asset"] = _shared_asset_function()
    return env.get_template("shared_head.html").render(shared_assets_base=shared_assets_base)


class CacheHeaders:
    """Pure ASGI middleware (no per-request task or wrapper objects): `Cache-Control: no-store` on every response, except a versioned static file."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        keepable = scope["method"] in ("GET", "HEAD") and scope["path"].lower().endswith(STATIC_EXTENSIONS) and bool(parse_qs(scope["query_string"].decode("latin-1")).get("v"))

        async def send_with_cache_header(message):
            if message["type"] == "http.response.start":
                from starlette.datastructures import MutableHeaders

                message.setdefault("headers", [])
                MutableHeaders(scope=message)["Cache-Control"] = IMMUTABLE if keepable and message["status"] in (200, 304) else NO_STORE
            await send(message)

        await self.app(scope, receive, send_with_cache_header)


def install_cache_headers(app) -> None:
    """Add `CacheHeaders` to a FastAPI/Starlette app (see the module docstring)."""
    app.add_middleware(CacheHeaders)
