"""Token creation service."""

import logging
import time
import uuid
from functools import cache
from typing import Any, Callable

from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import Client
from basic_oauth2_server.jwt import Algorithm, create_jwt, get_algorithm
from basic_oauth2_server.secrets import parse_secret

logger = logging.getLogger(__name__)


def create_access_token(
    client_id: str,
    algorithm: Algorithm,
    secret: bytes | None = None,
    private_key: bytes | None = None,
    scopes: list[str] | None = None,
    audience: str | None = None,
    expires_in: int = 3600,
    kid: str | None = None,
    issuer: str | None = None,
) -> str:
    """Create an OAuth access token JWT.

    Args:
        client_id: The client ID (will be the 'sub' claim).
        algorithm: The signing algorithm.
        secret: The shared secret (for HMAC).
        private_key: The private key (for asymmetric).
        scopes: List of granted scopes.
        audience: The token audience.
        expires_in: Token lifetime in seconds.
        kid: Optional key ID to include in the JWT header.
        issuer: Optional issuer URL for the 'iss' claim.

    Returns:
        The signed JWT access token.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": client_id,
        "iat": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
    }

    if issuer:
        claims["iss"] = issuer

    if scopes:
        claims["scope"] = " ".join(scopes)

    if audience:
        claims["aud"] = audience

    return create_jwt(
        claims, algorithm, secret=secret, private_key=private_key, kid=kid
    )


def make_token_factory(
    config: ServerConfig,
) -> Callable[[Client, list[str] | None, str | None], str]:
    """Captures the server config and returns a function to create access tokens for clients."""

    def _create_token(
        client: Client, scopes: list[str] | None, audience: str | None
    ) -> str:
        algorithm = get_algorithm(client.algorithm)

        if isinstance(algorithm, SymmetricAlgorithm):
            signing_secret = client.get_signing_secret()
            if not signing_secret:
                raise ValueError(
                    f"Client '{client.client_id}' has no signing secret configured"
                )
            return create_access_token(
                client_id=client.client_id,
                algorithm=algorithm,
                secret=signing_secret,
                scopes=scopes,
                audience=audience,
                expires_in=config.token_expires_in,
                issuer=config.app_url,
            )

        private_key_str, kid = config.get_private_key_for_algorithm(algorithm)
        if not private_key_str:
            raise ValueError(
                f"No private key configured for {algorithm}. "
                f"Set the appropriate --*-private-key option or environment variable."
            )
        private_key = _load_private_key(private_key_str)
        return create_access_token(
            client_id=client.client_id,
            algorithm=algorithm,
            private_key=private_key,
            scopes=scopes,
            audience=audience,
            expires_in=config.token_expires_in,
            kid=kid,
            issuer=config.app_url,
        )

    return _create_token


@cache
def _load_private_key(private_key_str: str) -> bytes:
    """Load and cache a private key from a file path or raw string."""
    return parse_secret(private_key_str)
