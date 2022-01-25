import base64
import json
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, TypedDict

import httpx
import jwt
import typeguard
import yarl


@dataclass
class Provider:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str

    def __str__(self):
        return f"Provider({self.issuer})"


class Configuration(TypedDict, total=False):
    """Subset of OpenID configuration JSON that we need"""

    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


class Key(TypedDict, total=False):
    kid: str
    kty: str
    alg: str
    crv: str
    x: str
    y: str
    # TODO add RSA bits


class Keys(TypedDict):
    keys: List[Key]


async def login_url(
    client: httpx.AsyncClient, provider: Provider, *, state: str, nonce: str = None
) -> str:
    # TODO make nonce optional
    configuration, _ = await metadata(client, provider)
    return str(
        yarl.URL(configuration["authorization_endpoint"]).with_query(
            client_id=provider.client_id,
            response_type="code",
            scope="openid profile email offline_access",
            redirect_uri=provider.redirect_uri,
            prompt="none",
            state=state,
            nonce=nonce,
        )
    )


async def get_tokens(
    client: httpx.AsyncClient,
    provider: Provider,
    *,
    code: str = None,
    refresh_token: str = None,
) -> Tuple[str, dict, dict]:
    logging.error("wtf %s", provider)
    assert (
        code or refresh_token
    ), "Either `code` or `refresh_token` kwargs must be provided"
    assert bool(code) ^ bool(
        refresh_token
    ), "Only one kwargs may be provided, `code` or `refresh_token`"
    configuration, keys = await metadata(client, provider)
    r = await client.post(
        configuration["token_endpoint"],
        data=dict(
            client_id=provider.client_id,
            client_secret=provider.client_secret,
            redirect_uri=provider.redirect_uri,
            **(
                dict(grant_type="authorization_code", code=code)
                if code
                else dict(grant_type="refresh_token", refresh_token="refresh_token")
            ),
        ),
    )
    r.raise_for_status()
    refresh_token = r.json().get("refresh_token")
    access_token_claims = _claims(r.json().get("access_token"), keys, provider)
    id_token_claims = _claims(r.json().get("id_token"), keys, provider)
    return refresh_token, access_token_claims, id_token_claims


# FIXME cache it
async def metadata(
    client: httpx.AsyncClient, provider: Provider
) -> Tuple[Configuration, Keys]:
    r = await client.get(
        str(yarl.URL(provider.issuer) / ".well-known/openid-configuration")
    )
    r.raise_for_status()
    configuration = _clean(
        f"openid configuration for {provider}", r.json(), type=Configuration
    )
    r = await client.get(configuration["jwks_uri"])
    r.raise_for_status()
    keys = _clean(f"openid keys for {provider}", r.json(), type=Keys)
    return configuration, keys


def _claims(token: Optional[str], keys: Keys, provider: Provider) -> Optional[dict]:
    kids = {k["kid"]: k for k in keys["keys"]}
    if not token:
        return
    head = _header(token)
    if not head or head.get("alg") != "ES256" or head.get("kid") not in kids:
        return
    try:
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
            issuer=provider.issuer,
            audience=provider.client_id,
        )
        # FIXME additional claims validation
        return claims
    except jwt.PyJWTError:
        logging.exception("FIXME")
        return


def _header(token: str) -> Optional[dict]:
    try:
        return json.loads(base64.b64decode(f"{token.split('.')[0]}==="))
    except Exception:
        pass


def _clean(name, value, type):
    try:
        value = {k: v for (k, v) in value.items() if k in type.__annotations__}
        typeguard.check_type(name, value, type)
        return value
    except (AttributeError, TypeError) as e:
        # TODO custom exception
        raise Exception(f"can't load {name}: {e}") from None
