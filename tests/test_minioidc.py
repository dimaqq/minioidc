import asyncio
import unittest

import pytest
from async_asgi_testclient import TestClient

import server

pytestmark = [pytest.mark.asyncio]


@pytest.fixture
async def client():
    async with TestClient(server.app) as client:
        yield client


@pytest.fixture
def config():
    with unittest.mock.patch(
        "os.environ",
        {
            "MINIOIDC_ORIGIN": "http://localhost:3000",
            "MINIOIDC_PROVIDER1_issuer": "https://server.test",
            "MINIOIDC_PROVIDER1_client_id": "cli1",
            "MINIOIDC_PROVIDER1_client_secret": "shh1",
            "MINIOIDC_PROVIDER2_issuer": "https://multitenant.test/tenant/abcd",
            "MINIOIDC_PROVIDER2_client_id": "cli2",
            "MINIOIDC_PROVIDER2_client_secret": "shh2",
        },
    ):
        origin, providers = server.configure()
        with unittest.mock.patch("server.ORIGIN", origin), unittest.mock.patch(
            "server.PROVIDERS", providers
        ):
            yield


async def test_homepage(config, client):
    r = await client.get("/")
    assert r.status_code == 200
    assert "html" in r.text


async def test_reject_no_state(config, client):
    r = await client.get("/cb")
    assert r.status_code == 401
    assert r.json() == {"detail": unittest.mock.ANY}


async def test_reject_bad_state(config, client):
    r = await client.get("/cb?state=foobar")
    assert r.status_code == 401
    assert r.json() == {"detail": unittest.mock.ANY}


@pytest.fixture
def state():
    s = server.State(123, "foobarbaz", "1")
    server.STATES["foobarba"] = s
    yield s
    del server.STATES["foobarba"]


async def test_reject_no_code(config, client, state):
    r = await client.get(f"/cb?state={state.state}")
    assert r.status_code == 401
    assert r.json() == {"detail": unittest.mock.ANY}


async def test_propagate_errors(config, client, state):
    r = await client.get(f"/cb?state={state.state}&code=42")
    assert r.status_code == 401
    assert r.json() == {}
    assert r.json() == {"detail": unittest.mock.ANY}
