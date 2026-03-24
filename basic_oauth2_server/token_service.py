"""Module for bundling access and refresh token creation logic.

I called it a service, but its just functions, and not dependency-inversed generic service nonsense. Deal with it.
"""

from basic_oauth2_server.config import ServerConfig

from .jwt import (
    create_access_token,
    get_algorithm,
    SymmetricAlgorithm,
)
from .db import Client


def create_access_token_for_client(
    config: ServerConfig,
    client: Client,
    scopes: list[str] | None = None,
    audience: str | None = None,
    subject: str | None = None,
) -> str:
    """Create an access token for the given client and the current server config.

    For symmetric algorithms (HS*), uses the client's signing secret.
    For asymmetric algorithms (RS*, ES*, EdDSA), uses the server's private key matching the algorithm family.

    Args:
        config: The server configuration, used to load private keys for asymmetric algorithms.
        client: The client for which to create the access token. The client's configured algorithm and signing secret (for symmetric algorithms) will be used.
        scopes: Optional list of scopes to include in the token's "scope" claim.
        audience: Optional audience to include in the token's "aud" claim.
    """
    algorithm = get_algorithm(client.algorithm)

    if isinstance(algorithm, SymmetricAlgorithm):
        signing_secret = client.get_signing_secret()
        if not signing_secret:
            raise ValueError(
                f"Client '{client.client_id}' has no signing secret configured"
            )
        return create_access_token(
            subject=subject or client.client_id,
            algorithm=algorithm,
            secret=signing_secret,
            scopes=scopes,
            audience=audience,
            expires_in=config.token_expires_in,
            issuer=config.app_url,
        )
    else:
        private_key, kid = config.load_private_key(algorithm)
        return create_access_token(
            subject=subject or client.client_id,
            algorithm=algorithm,
            private_key=private_key,
            scopes=scopes,
            audience=audience,
            expires_in=config.token_expires_in,
            kid=kid,
            issuer=config.app_url,
        )


def create_client_refresh_token(
    server: ServerConfig,
):
    # TODO: implement refresh token creation when we need it for auth code flow
    pass
