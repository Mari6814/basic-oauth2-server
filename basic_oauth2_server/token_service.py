"""Helpers for issuing OAuth access and refresh tokens."""

from basic_oauth2_server.config import ServerConfig

from .jwt import (
    create_access_token,
    get_algorithm,
    SymmetricAlgorithm,
)
from .db import Client, create_refresh_token


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

    Returns:
        A signed JWT access token.
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
            client_id=client.client_id,
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
            client_id=client.client_id,
        )


def create_refresh_token_for_client(
    config: ServerConfig,
    client: Client,
    user_id: str,
    scopes: list[str] | None = None,
    audience: str | None = None,
) -> str:
    """Create and persist an opaque refresh token for a client and user.

    Args:
        config: Server configuration containing DB path and refresh TTL.
        client: Client the refresh token belongs to.
        user_id: Authenticated resource owner username.
        scopes: Optional scopes tied to the refresh token.
        audience: Optional audience tied to the refresh token.

    Returns:
        The opaque refresh token string.
    """
    return create_refresh_token(
        db_path=config.db_path,
        client_id=client.client_id,
        user_id=user_id,
        scope=" ".join(scopes) if scopes else None,
        audience=audience,
        expires_in=config.refresh_token_expires_in,
    )
