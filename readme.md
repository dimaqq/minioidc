# OIDA CLI

![](oida-icon.png)
Example client that implements OpenID Connect confidential client using code flow

#### Quick start

```command
poetry run uvicorn server:app --reload [--port 3000]
```

#### Configuration

The test client expects following configuration:

```command
# Where this client is ran; important for OIDC security via redirect_uri
# Use HTTPS (e.g. ngrok) to test against production OIDC servers
export MINIOIDC_ORIGIN="http://localhost:3000"

# Client ids and secrets are issued by the OIDC server
export MINIOIDC_PROVIDER1_issuer="http://server:port"
export MINIOIDC_PROVIDER1_client_id="client-id-goes-here"
export MINIOIDC_PROVIDER1_client_secret="secret-goes-here"

export MINIOIDC_PROVIDER2_issuer="http://server:port"
export MINIOIDC_PROVIDER2_client_id="client-id-goes-here"
export MINIOIDC_PROVIDER2_client_secret="secret-goes-here"
```
