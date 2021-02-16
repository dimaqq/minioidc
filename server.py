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


sessions: typing.Dict[str, Session] = {}


@app.get("/items/", response_class=HTMLResponse)
async def homepage(
    response: Response,
    id: typing.Optional[str] = Cookie(None),
    logout: typing.Optional[str] = Query(None),
):
    if id not in sessions:
        id = secrets.token_hex(16)
        sessions[id] = Session(time.time())
        response.set_cookie("session", id)

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
