from __future__ import annotations

import base64
import dataclasses
import json
import logging
import os
import secrets
import time
from typing import Dict, Optional, Tuple

import httpx
import jwt
import yarl
from fastapi import Depends, FastAPI, Query, Response
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logging.basicConfig(level=logging.INFO)
app = FastAPI()


@app.get("/", response_class=HTMLResponse)
async def homepage():
    return f"""
    <html>
        <head>
            <title>Example client that implements OpenID Connect confidential client using code flow</title>
            <link rel="shortcut icon" href="{ICON}"/>
            <script>{JS}</script>
            <style>{CSS}></style>
        </head>
        <body>
            <h1>OpenID Connect test client</h1>
            <div class="system">
                <div>System status</div>
                <div></div>
                <label>FastAPI token</label>
                <input id="fastapi_token"></input>
                <div>First Tenant</div>
                <div><a href="/login?config=1">Login with first</a></div>
                <div>Second Tenant</div>
                <div><a href="/login?config=2">Login with second</a></div>
                <div></div>
                <button id="logout">Logout</button>
            </div>
            <div class="status">
                <label>Id token claims</label>
                <label>Access token claims</label>
                <label>Server debug: session, etc.</label>
                <textarea id="id_token" placeholder="..."></textarea>
                <textarea id="access_token" placeholder="..."></textarea>
                <textarea id="status-rest" placeholder="..."></textarea>
                <div></div><div></div><button id="recheck">Re-check</button>
            </div>
        </body>
    </html>
    """.strip()


@dataclasses.dataclass
class Session:
    created: float
    fastapi_token: str
    config: str
    refresh_token: Optional[str]
    access_token: Optional[Dict]
    id_token: Optional[Dict]
    error: Optional[str]
    error_description: Optional[str]


auth = HTTPBearer()


def valid_session(
    authorization: HTTPAuthorizationCredentials = Depends(auth),
) -> Session:
    try:
        session = SESSIONS[authorization.credentials[:8]]
        if not secrets.compare_digest(authorization.credentials, session.fastapi_token):
            raise KeyError()
        return session
    except KeyError:
        raise HTTPException(403, "Not authenticated")


@app.post("/status")
async def status(session: Session = Depends(valid_session)):
    await may_refresh(session)
    tmp = dataclasses.asdict(session)
    tmp["refresh_token"] = bool(tmp["refresh_token"])
    return tmp


@app.post("/logout")
def logout(session: Session = Depends(valid_session)):
    try:
        del SESSIONS[session.fastapi_token[:8]]
    except KeyError:
        logging.exception("WTF")


@app.get("/login")
async def login(config: Optional[str] = Query(None)):
    try:
        cfg = PROVIDERS[config or "missing"]
    except KeyError:
        raise HTTPException(422, "config parameter missing or unknown")

    async with httpx.AsyncClient() as client:
        try:
            configuration, keys = await metadata(client, config)
        except httpx.HTTPStatusError as e:
            raise HTTPException(400, e.response.text)

    state = secrets.token_hex(20)
    nonce = secrets.token_hex(16)
    STATES[state[:8]] = State(time.time(), state, config)
    cleanup(STATES)
    return RedirectResponse(
        str(
            yarl.URL(configuration["authorization_endpoint"]).with_query(
                client_id=cfg["client_id"],
                response_type="code",
                scope="openid profile email offline_access",
                redirect_uri=f"{ORIGIN}/cb",
                prompt="none",
                state=state,
                nonce=nonce,
            )
        )
    )


@app.get("/cb")
async def callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
):
    try:
        s = STATES[state[:8]]
        if not secrets.compare_digest(s.state, state):
            raise KeyError()
        cfg = PROVIDERS[s.config]
    except (KeyError, TypeError):
        raise HTTPException(401, "Ignoring callback because state didn't match")

    async with httpx.AsyncClient() as client:
        try:
            configuration, keys = await metadata(client, s.config)
            r = await client.post(
                configuration["token_endpoint"],
                data=dict(
                    grant_type="authorization_code",
                    client_id=cfg["client_id"],
                    client_secret=cfg["client_secret"],
                    code=code,
                    redirect_uri=f"{ORIGIN}/cb",
                ),
            )
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(401, e.response.json())

    fastapi_token = secrets.token_hex(20)
    SESSIONS[fastapi_token[:8]] = Session(
        time.time(),
        fastapi_token,
        s.config,
        r.json().get("refresh_token"),
        claims(r.json().get("access_token"), keys, s.config),
        claims(r.json().get("id_token"), keys, s.config),
        error,
        error_description,
    )
    cleanup(SESSIONS)
    return RedirectResponse(f"/#{fastapi_token}")


async def may_refresh(session: Session):
    if not session.refresh_token:
        return
    tokens = [getattr(session, name) for name in ("access_token", "id_token")]
    if not any(t and t["exp"] < time.time() for t in tokens):
        return
    async with httpx.AsyncClient() as client:
        try:
            configuration, keys = await metadata(client, session.config)
            r = await client.post(
                configuration["token_endpoint"],
                data=dict(
                    grant_type="refresh_token",
                    client_id=PROVIDERS[session.config]["client_id"],
                    client_secret=PROVIDERS[session.config]["client_secret"],
                    refresh_token=session.refresh_token,
                    redirect_uri=f"{ORIGIN}/cb",
                ),
            )
            session.access_token = claims(
                r.json()["access_token"], keys, session.config
            )
            session.id_token = claims(r.json()["id_token"], keys, session.config)
        except httpx.HTTPStatusError as e:
            logging.exception("failed to refresh token")


@dataclasses.dataclass
class State:
    created: float
    state: str
    config: str


SESSIONS: Dict[str, Session] = {}
STATES: Dict[str, State] = {}
DEAFULT_DURATION = 3600
DEFAULT_LIMIT = 1000


def cleanup(what):
    def clean(expiry):
        for k, s in list(what.items()):
            if s.created < expiry:
                del what[k]

    duration = DEAFULT_DURATION
    now = time.time()
    clean(now - duration)

    while len(what) > DEFAULT_LIMIT and duration:
        duration //= 2
        clean(now - duration)


def claims(token: Optional[str], keys: dict, config: str) -> Optional[dict]:
    kids = {k["kid"]: k for k in keys["keys"]}
    if not token:
        return
    head = header(token)
    if not head or head.get("alg") != "ES256" or head.get("kid") not in kids:
        return
    claims = jwt.decode(
        token,
        # https://github.com/jpadilla/pyjwt/issues/603
        key=jwt.api_jwk.PyJWK({"alg": "ES256", **kids[head["kid"]]}).key,
        algorithms=["ES256"],  # FIXME what?
        options=dict(
            verify_signature=True,
            require_exp=True,
            verify_exp=True,
            verify_iss=True,
            verify_aud=True,
            require_iat=False,
            require_nbf=False,
        ),
        issuer=PROVIDERS[config]["issuer"],
        audience=PROVIDERS[config]["client_id"],
    )
    # FIXME additional claims validation
    return claims


def header(token: str) -> dict:
    try:
        return json.loads(base64.b64decode(f"{token.split('.')[0]}==="))
    except Exception:
        logging.exception("could not parse token")


async def metadata(client, config: str) -> Tuple[dict, dict]:
    r = await client.get(
        str(yarl.URL(PROVIDERS[config]["issuer"]) / ".well-known/openid-configuration")
    )
    r.raise_for_status()
    configuration = r.json()
    r = await client.get(configuration["jwks_uri"])
    r.raise_for_status()
    return configuration, r.json()


ORIGIN = os.environ.get("MINIOIDC_ORIGIN", "")

PROVIDERS = {"1": {}, "2": {}}
for name in ("issuer", "client_id", "client_secret"):
    PROVIDERS["1"][name] = os.environ.get(f"MINIOIDC_PROVIDER1_{name}", "")
    PROVIDERS["2"][name] = os.environ.get(f"MINIOIDC_PROVIDER2_{name}", "")


SAMPLE_OIDC_CONFIGURATION = {
    "issuer": "http://server.com",
    "authorization_endpoint": "http://server.com/authorize",
    "response_types_supported": ["code"],
    "token_endpoint": "http://server.com/oauth/token",
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["ES256"],
    "jwks_uri": "http://server.com/oauth/keys",
    "scopes_supported": ["email", "offline_access", "openid", "profile"],
    "userinfo_endpoint": "http://server.com/oauth/userinfo",
}


JS = """
"use strict";
const state = {};
const new_token = window.location.hash.split("#")[1];
if (new_token) {
  window.location.hash = "";
  localStorage.setItem("fastapi_token", new_token);
}
state.fastapi_token = localStorage.getItem("fastapi_token");
console.log("FastAPI token is", state.fastapi_token);

const logout = async () => {
  if (state.fastapi_token) {
    const resp = await fetch("/logout", {method: "POST", headers: {Authorization: `Bearer ${ state.fastapi_token }`}});
    const data = await resp.json();
    console.log("logout", data);
  }
  localStorage.removeItem("fastapi_token");
  state.fastapi_token = null;
  await status();
};

const status = async () => {
  let data;
  if (state.fastapi_token) {
    const resp = await fetch("/status", {method: "POST", headers: {Authorization: `Bearer ${ state.fastapi_token }`}});
    data = await resp.json();
    console.log("status", data);
  }
  else {
    data = {system_error: "no FastAPI token"};
  }
  const {id_token, access_token, ...status_rest} = data;
  state.id_token = id_token;
  state.access_token = access_token;
  state.status_rest = status_rest;
  render();
};

const render = () => {
  document.querySelector("#id_token").value = JSON.stringify(state.id_token, null, 2);
  document.querySelector("#access_token").value = JSON.stringify(state.access_token, null, 2);
  document.querySelector("#status-rest").value = JSON.stringify(state.status_rest, null, 2);
  document.querySelector("#fastapi_token").value = state.fastapi_token;
};

window.onload = () => {
  document.querySelector("#logout").onclick = logout;
  document.querySelector("#recheck").onclick = status;
  status();
  setInterval(status, 1000);
};
"""

CSS = """
body {
  width: 1800px;
  margin: 20px auto 20px auto;
  display: flex;
  flex-direction: column;
}

.system {
  display: grid;
  margin: 20px 0 60px 0;
  border: 1px solid rgba(0,0,0,.3);
  border-radius: 5px;
  padding: 10px;
  grid-template-columns: 1fr 1fr;
  gap: 10px 10px;
}

#logout {
  margin-left: auto;
}

textarea {
  flex: auto;
}

.status {
  height: 400px;
  border: 1px solid rgba(0,0,0,.3);
  border-radius: 5px;
  padding: 10px;
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  grid-template-rows: max-content 1fr max-content;
  gap: 10px 10px;
  grid-template-areas:
    ". . ."
    ". . ."
    ". . .";
}

#recheck {
  flex: none;
  margin-left: auto;
}
"""


ICON = """data:image/png;base64,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"""
