from dataclasses import dataclass
from typing import Optional, Tuple

import jwt
import yarl
from httpx import AsyncClient


@dataclass
class Provider:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str


async def get_tokens(
    client: AsyncClient,
    provider: Provider,
    *,
    code: str = None,
    refresh_token: str = None,
) -> Tuple[str, dict, dict]:
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
async def metadata(client: AsyncClient, provider: Provider) -> Tuple[dict, dict]:
    r = await client.get(
        str(yarl.URL(provider.issuer) / ".well-known/openid-configuration")
    )
    r.raise_for_status()
    configuration = r.json()
    r = await client.get(configuration["jwks_uri"])
    r.raise_for_status()
    return configuration, r.json()


def _claims(token: Optional[str], keys: dict, provider: Provider) -> Optional[dict]:
    kids = {k["kid"]: k for k in keys["keys"]}
    if not token:
        return
    head = _header(token)
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
        issuer=provider.issuer,
        audience=provider.client_id,
    )
    # FIXME additional claims validation
    return claims


def _header(token: str) -> Optional[dict]:
    try:
        return json.loads(base64.b64decode(f"{token.split('.')[0]}==="))
    except Exception:
        pass
