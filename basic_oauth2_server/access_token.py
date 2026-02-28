"""Module for OAuth2 access token logic."""

import time
from typing import Any
import uuid

from basic_oauth2_server.jwt import Algorithm, create_jwt


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
