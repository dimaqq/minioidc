from __future__ import annotations

import dataclasses
import logging
import secrets
import time
from typing import Dict, Optional, Tuple

from fastapi import Cookie, FastAPI, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse

COOKIE_DURATION = 3600
COOKIE_LIMIT = 1000
logging.basicConfig(level=logging.INFO)
app = FastAPI()


@dataclasses.dataclass
class State:
    created: float


@dataclasses.dataclass
class Session:
    created: float
    refresh_token: Optional[str]
    access_token: Optional[Dict]
    id_token: Optional[Dict]
    error: Optional[str]
    error_description: Optional[str]


sessions: Dict[str, Session] = {}
states: Dict[str, State] = {}


def cleanup_sessions():
    def clean(expiry):
        for k, s in sessions.items():
            if s.created < expiry:
                del sessions[k]

    duration = COOKIE_DURATION
    now = time.time()
    clean(now - duration)

    while len(sessions) > COOKIE_LIMIT and duration:
        duration //= 2
        clean(now - duration)


@app.post("/logout")
def logout(session: Optional[str] = Cookie(None)):
    try:
        if session:
            del sessions[session]
    except KeyError:
        pass
    return RedirectResponse("/")


JS = """
use strict;
const new_token = window.location.hash;
if (new_token) {
  window.location.hash = "";
  localStorage.setItem("fastapi_token", new_token);
}
const fastapi_token = localStorage.getItem("fastapi_token");
"""


@app.get("/cb", response_class=HTMLResponse)
async def callback(
    response: Response,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
):
    fastapi_token = secrets.token_hex(16)
    refresh_token, access_token, id_token = await get_tokens(code)
    session = sessions[fastapi_token] = Session(
        time.time(), refresh_token, access_token, id_token, error, error_description
    )
    cleanup_sessions()
    return RedirectResponse(f"/#fastapi_token")


@app.get("/status")
async def status():
    return {"access_token": {"fix": "me"}, "id_token": {"fix": "me"}}


@app.get("/", response_class=HTMLResponse)
async def homepage():
    return f"""
    <html>
        <head>
            <title>Example client that implements OpenID Connect confidential client using code flow</title>
            <script>{JS}</script>
        </head>
        <body>
            <div>FIXME</div>
            <form action="/logout" method="post">
                <input type="submit" value="logout"/>
            </form>
        </body>
    </html>
    """.strip()


async def get_tokens(code) -> Tuple:
    return "rrr", {"a": 42}, {"id": 42}
