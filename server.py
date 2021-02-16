from __future__ import annotations

import dataclasses
import secrets
import time
import typing

from fastapi import Cookie, FastAPI, Query, Response
from fastapi.responses import HTMLResponse

app = FastAPI()


@dataclasses.dataclass
class Session:
    created: float


sessions: typing.Dict[str, Session] = {}o

def cleanup_sessions():
    def clean(expiry):
        for k, s in sesssions.items():
            if s.created < expiry:
                del sessions[k]

    duration = 3600
    now = time.time()
    clean(now - expiry)

    while len(sessions) > 1000 and duration:
        duration //= 2
        clean(now - expiry)


@app.get("/items/", response_class=HTMLResponse)
async def homepage(
    response: Response,
    session: typing.Optional[str] = Cookie(None),
    logout: typing.Optional[str] = Query(None),
):
    if session not in sessions:
        session = secrets.token_hex(16)
        s = sessions[session] = Session(time.time())
        response.set_cookie("session", session)
        cleanup_sessions()
    else:
        s = sessions[session]

    return """
    <html>
        <head>
            <title>Example client that implements OpenID Connect confidential client using code flow</title>
        </head>
        <body>
            <div>FIXME</div>
        </body>
    </html>
    """.strip()
