import asyncio
import base64
import logging
import unittest

import cryptography.hazmat.primitives.asymmetric.ec
import jwt
import pytest
from async_asgi_testclient import TestClient

import minioidc
import server

pytestmark = [pytest.mark.asyncio]


@pytest.fixture
async def client():
    async with TestClient(server.app) as client:
        yield client


@pytest.fixture
def config():
    fakeenv = {
        "MINIOIDC_ORIGIN": "http://localhost:3000",
        "MINIOIDC_PROVIDER1_issuer": "https://server.test",
        "MINIOIDC_PROVIDER1_client_id": "cli1",
        "MINIOIDC_PROVIDER1_client_secret": "shh1",
        "MINIOIDC_PROVIDER2_issuer": "https://multitenant.test/tenant/abcd",
        "MINIOIDC_PROVIDER2_client_id": "cli2",
        "MINIOIDC_PROVIDER2_client_secret": "shh2",
    }
    with unittest.mock.patch("os.environ", fakeenv):
        origin, providers = server.configure()
        with unittest.mock.patch("server.ORIGIN", origin), unittest.mock.patch(
            "server.PROVIDERS", providers
        ):
            yield fakeenv


def test_test_key(config):
    provider = server.PROVIDERS["1"]
    token = jwt.encode(
        payload={"iss": "https://server.test", "aud": "cli1"},
        headers={"kid": "test"},
        key=TEST_PRIVATE_KEY,
        algorithm="ES256",
    )
    assert minioidc._header(token) == {"alg": "ES256", "kid": "test", "typ": "JWT"}
    assert minioidc._claims(token, {"keys": [TEST_PUBLIC_JWK]}, provider) == {
        "iss": provider.issuer,
        "aud": provider.client_id,
    }


async def mock_http_client_get(url, data=None):
    if url == "https://server.test/.well-known/openid-configuration":
        data = {
            "issuer": "https://server.test",
            "authorization_endpoint": "https://server.test/authorize",
            "response_types_supported": ["code"],
            "token_endpoint": "https://server.test/token",
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "jwks_uri": "https://server.test/keys",
            "scopes_supported": ["email", "offline_access", "openid", "profile"],
            "userinfo_endpoint": "https://server.test/userinfo",
        }
    elif url == "https://server.test/keys":
        data = {"keys": [TEST_PUBLIC_JWK]}
    elif url == "https://server.test/token":
        data = {}
    else:
        assert not url, "test debug only"
    rv = unittest.mock.Mock()
    rv.status_code = 200
    rv.json.return_value = data
    return rv


@pytest.fixture
async def mock_http():
    with unittest.mock.patch("httpx.AsyncClient") as AS:
        async with AS() as client:
            client.get = mock_http_client_get
            client.post = mock_http_client_get
            yield client


@pytest.fixture
def state():
    s = server.State(123, "foobarbaz", "1")
    server.STATES["foobarba"] = s
    yield s
    del server.STATES["foobarba"]


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


async def test_reject_no_code(config, client, state):
    r = await client.get(f"/cb?state={state.state}")
    assert r.status_code == 401
    assert r.json() == {"detail": unittest.mock.ANY}


@pytest.mark.skip("decision needed for error handling")
async def test_propagate_errors(config, client, state):
    r = await client.get(f"/cb?state={state.state}&error=eee")
    assert r.status_code == 401
    assert r.json() == {}
    assert r.json() == {"detail": unittest.mock.ANY}


async def test_authorization_code(config, client, state, mock_http):
    r = await client.get(f"/cb?state={state.state}&code=42")
    assert r.status_code == 401
    assert r.json() == {}
    assert r.json() == {"detail": unittest.mock.ANY}


TEST_PUBLIC_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "alg": "ES256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "kid": "test",
}

TEST_PRIVATE_KEY = cryptography.hazmat.primitives.asymmetric.ec.derive_private_key(
    int.from_bytes(
        base64.urlsafe_b64decode("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE" + "==="),
        "big",
    ),
    cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
)
