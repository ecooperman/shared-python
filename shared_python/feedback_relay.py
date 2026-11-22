"""Send feedback from inside an app: the app's own `POST /api/feedback`, which passes the message on to the dashboard's inbox.

Every app's menu has a Send feedback entry that opens one small form (shared-assets) and posts it HERE, on the app's own address, so the
app's cross-site guard (shared_python.csrf) and its own sign-in gate apply as for any other action: only someone with an account in the
app gets this far. The app then hands the message to the dashboard on this machine (`POST /internal/feedback`, settings.DASHBOARD_API_BASE),
with the app's key and the person's own session cookie, and the dashboard checks the sign-in again, keeps the message, and tells the
administrator. So there is one inbox, separated by app, and no app keeps messages of its own.

    feedback_relay.install(app, "lists", dependencies=[Depends(current_user)])   # an app with its own sign-in dependency
    feedback_relay.install(app, "finances")                                      # behind accounts_gate's middleware already
"""
from typing import Optional, Sequence

import requests
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from . import auth, settings

PATH = "/api/feedback"
TIMEOUT = 5
MAX_BODY = 4000


class FeedbackIn(BaseModel):
    kind: str
    body: str = Field(max_length=MAX_BODY * 2)  # the dashboard trims and checks it and answers in a sentence
    page: Optional[str] = Field(default=None, max_length=300)


def install(app, app_key: str, dependencies: Sequence = ()) -> None:
    router = APIRouter(dependencies=list(dependencies))

    @router.post(PATH)
    def send_feedback(body: FeedbackIn, request: Request):
        base = settings.DASHBOARD_API_BASE
        if not base:
            raise HTTPException(status_code=503, detail="Feedback isn't set up on this server.")
        headers = {}
        cookie_name = auth.oidc_cookie_name()
        if cookie_name and request.cookies.get(cookie_name):
            headers["Cookie"] = f"{cookie_name}={request.cookies[cookie_name]}"  # only the sign-in cookie, nothing else of theirs
        try:
            resp = requests.post(base.rstrip("/") + "/internal/feedback", json={"app": app_key, **body.model_dump()}, headers=headers, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            raise HTTPException(status_code=502, detail="Couldn't reach the feedback inbox just now. Please try again in a moment.")
        if resp.status_code == 200:
            return resp.json()
        try:
            detail = resp.json().get("detail")
        except ValueError:
            detail = None
        if resp.status_code in (400, 429) and isinstance(detail, str):
            raise HTTPException(status_code=resp.status_code, detail=detail)  # a sentence meant for the person
        if resp.status_code == 401:
            raise HTTPException(status_code=401, detail="Please sign in again.")
        raise HTTPException(status_code=502, detail="The feedback inbox didn't take that. Please try again in a moment.")

    app.include_router(router)
