"""Telling the dashboard's "does this person have an account here?" check apart from a person using an app.

The dashboard asks each app whether someone has an account by calling its /api/me with THAT PERSON'S session cookie (dashboard/app/access.py),
and the shared navigation does so, through the dashboard, on pages anyone opens. That is the dashboard looking, not the person using the
app, so such a call carries this header and an app never records it as "last seen" (shared_python.usage).

No dependencies on purpose: the dashboard (which has no database) imports this too."""

PROBE_HEADER = "X-Brassworks-Probe"


def is_probe(request) -> bool:
    """True for the dashboard's account check (see PROBE_HEADER)."""
    return request.headers.get(PROBE_HEADER) == "1"
