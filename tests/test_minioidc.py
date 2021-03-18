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


async def test_something(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "html" in resp.text

    resp = await client.get("/json")
    assert resp.status_code == 404
    # assert resp.json() == {"hello": "world"}


@pytest.fixture
def config():
    with unittest.mock.patch(
        "os.environ",
        {
            "MINIOIDC_ORIGIN": "http://localhost:3000",
            "MINIOIDC_PROVIDER1_issuer": "https://server.test",
            "MINIOIDC_PROVIDER1_client_id": "cli1",
            "MINIOIDC_PROVIDER1_client_secret": "sss1",
            "MINIOIDC_PROVIDER2_issuer": "https://multitenant.test/tenant/abcd",
            "MINIOIDC_PROVIDER2_client_id": "cli2",
            "MINIOIDC_PROVIDER2_client_secret": "cli2",
        },
    ):
        server.configure()


async def test_foo(config):
    ...
