"""The head lines every page shares live in one file; an app's templates include it, and the Python-built sign-in page uses the same lines."""
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.templating import Jinja2Templates

from shared_python import oidc_login, pages

BASE = "https://static.example.org"


@pytest.fixture(autouse=True)
def no_shared_assets_folder(tmp_path, monkeypatch):
    """By default the shared files are 'not found', so addresses have no ?v (a test that wants versions makes the folder)."""
    monkeypatch.setattr(pages, "SHARED_ASSETS_DIR", tmp_path / "no-such-folder")


def render(tmp_path, body: str) -> str:
    (tmp_path / "page.html").write_text(body)
    templates = Jinja2Templates(directory=str(tmp_path))
    pages.install(templates)
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b"", "server": ("t", 80), "scheme": "http"})
    return templates.TemplateResponse(request, "page.html", {"shared_assets_base": BASE}).body.decode()


def test_a_template_can_include_the_shared_head_and_keeps_its_own_lines(tmp_path):
    html = render(tmp_path, '<head>{% include "shared_head.html" %}<title>Mine</title><link rel="stylesheet" href="style.css"></head>')
    for line in (f'href="{BASE}/theme.css"', f'href="{BASE}/logo.svg"', f'href="{BASE}/favicon.png"', f'src="{BASE}/theme-init.js"', 'charset="utf-8"', "viewport"):
        assert line in html
    assert "<title>Mine</title>" in html and 'href="style.css"' in html


def test_the_apps_own_template_folder_wins_over_the_shared_one(tmp_path):
    (tmp_path / "shared_head.html").write_text("MINE")
    assert render(tmp_path, '{% include "shared_head.html" %}') == "MINE"


def test_the_python_built_page_uses_the_same_lines_and_escapes_the_address():
    html = pages.head_html('https://x.example/"><script>')
    assert "<script>" not in html.replace('<script src=', "") and "&#34;&gt;&lt;script&gt;" in html
    assert pages.head_html(BASE) == render_plain()


def render_plain() -> str:
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(str(pages.TEMPLATES_DIR)))
    env.globals["shared_asset"] = lambda name: f"{BASE}/{name}"
    return env.get_template("shared_head.html").render(shared_assets_base=BASE)


def test_the_sign_in_error_page_carries_the_shared_head():
    html = oidc_login._page("Title", "Message").body.decode()
    assert pages.head_html(oidc_login._assets_base()).strip() in html


# --- versioned file addresses ---------------------------------------------------------------------------------------------------------


def test_a_shared_file_gets_a_version_that_changes_only_when_the_file_does(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "theme.js").write_text("one")
    monkeypatch.setattr(pages, "SHARED_ASSETS_DIR", shared)
    first = render(tmp_path, "{{ shared_asset('theme.js') }}")
    assert first.startswith(f"{BASE}/theme.js?v=") and len(first.split("?v=")[1]) == 10
    assert render(tmp_path, "{{ shared_asset('theme.js') }}") == first
    (shared / "theme.js").write_text("two!")
    assert render(tmp_path, "{{ shared_asset('theme.js') }}") != first


def test_a_missing_file_gets_its_plain_address_so_a_page_never_breaks(tmp_path):
    assert render(tmp_path, "{{ shared_asset('theme.js') }}") == f"{BASE}/theme.js"
    assert render(tmp_path, "{{ asset('nothing.js') }}") == "/nothing.js"


def test_the_apps_own_file_is_versioned_from_its_static_folder(tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "list.js").write_text("code")
    (tmp_path / "page.html").write_text("{{ asset('/list.js') }}|{{ asset('list.js') }}")
    templates = Jinja2Templates(directory=str(tmp_path))
    pages.install(templates, static_dir=static)
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b"", "server": ("t", 80), "scheme": "http"})
    one, two = templates.TemplateResponse(request, "page.html", {}).body.decode().split("|")
    assert one == two and one.startswith("/list.js?v=")


def test_the_shared_head_carries_versions_when_the_files_are_there(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    shared.mkdir()
    for name in ("theme.css", "logo.svg", "favicon.png", "theme-init.js"):
        (shared / name).write_text(name)
    monkeypatch.setattr(pages, "SHARED_ASSETS_DIR", shared)
    html = pages.head_html(BASE)
    assert html.count("?v=") == 4 and f"{BASE}/theme.css?v=" in html


# --- cache headers ------------------------------------------------------------------------------------------------------------------------


@pytest.fixture()
def cached_app(tmp_path):
    (tmp_path / "list.js").write_text("code")
    (tmp_path / "page.html").write_text("<p>hi</p>")
    app = FastAPI()
    pages.install_cache_headers(app)

    @app.get("/api/thing")
    def thing():
        return {"a": 1}

    @app.get("/api/boom")
    def boom():
        return JSONResponse({"detail": "no"}, status_code=400)

    app.mount("/", StaticFiles(directory=str(tmp_path), html=True), name="static")
    return TestClient(app)


def test_everything_is_no_store_as_before(cached_app):
    for path in ("/api/thing", "/api/boom", "/page.html", "/list.js", "/nothing-here.js"):
        assert cached_app.get(path).headers["cache-control"] == "no-store", path


def test_a_versioned_static_file_is_kept_for_a_year(cached_app):
    got = cached_app.get("/list.js?v=abc123")
    assert got.status_code == 200 and got.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert cached_app.get("/list.js?v=").headers["cache-control"] == "no-store"  # an empty version is not a version


def test_only_a_static_file_type_can_be_kept_and_a_missing_one_never_is(cached_app):
    assert cached_app.get("/page.html?v=abc").headers["cache-control"] == "no-store"
    assert cached_app.get("/api/thing?v=abc").headers["cache-control"] == "no-store"
    assert cached_app.get("/missing.js?v=abc").headers["cache-control"] == "no-store"  # a 404 must not be remembered
    assert cached_app.post("/list.js?v=abc").headers["cache-control"] == "no-store"
