"""The head lines every page shares live in one file; an app's templates include it, and the Python-built sign-in page uses the same lines."""
from starlette.requests import Request
from starlette.templating import Jinja2Templates

from shared_python import oidc_login, pages

BASE = "https://static.example.org"


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

    return Environment(loader=FileSystemLoader(str(pages.TEMPLATES_DIR))).get_template("shared_head.html").render(shared_assets_base=BASE)


def test_the_sign_in_error_page_carries_the_shared_head():
    html = oidc_login._page("Title", "Message").body.decode()
    assert pages.head_html(oidc_login._assets_base()).strip() in html
