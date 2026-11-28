"""The lines every page's <head> shares, kept in ONE file (`templates/shared_head.html`): the character set, the viewport, the shared theme
stylesheet, the favicons and `theme-init.js` (which sets light/dark before the first paint).

An app's Jinja templates include it:

    templates = Jinja2Templates(directory="templates")
    pages.install(templates)            # once, where `templates` is made

    <head>
      {% include "shared_head.html" %}
      <title>Lists</title>
      ...the page's own lines...
    </head>

The include reads `shared_assets_base` from the page's context, as every page already passes it. A page that is not a Jinja template (the
sign-in error page in `oidc_login`) uses `head_html(base)` for the same lines. The icons are tags in the HTML itself (not added later by
JavaScript), so they show from the first paint, in link previews and with scripts off."""
from pathlib import Path


TEMPLATES_DIR = Path(__file__).parent / "templates"


def install(templates) -> None:
    """Let this app's templates `{% include "shared_head.html" %}`. `templates` is a starlette `Jinja2Templates`; the app's own folder is searched first."""
    from jinja2 import ChoiceLoader, FileSystemLoader

    templates.env.loader = ChoiceLoader([templates.env.loader, FileSystemLoader(str(TEMPLATES_DIR))])


def head_html(shared_assets_base: str) -> str:
    """The same lines as a string, for a page built in Python."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=select_autoescape(["html"]))
    return env.get_template("shared_head.html").render(shared_assets_base=shared_assets_base)
