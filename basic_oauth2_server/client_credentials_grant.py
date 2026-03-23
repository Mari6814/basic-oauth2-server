"""Handle the client_credentials grant type."""

import logging
import base64
from typing import Literal

from .config import ServerConfig
from .exceptions import (
    InvalidAudienceException,
    InvalidClientException,
    InvalidRequestException,
    InvalidScopeException,
    OAuthServerErrorException,
)
from .db import get_client, touch_client_last_used
from .token_service import create_access_token_for_client

logger = logging.getLogger(__name__)


def handle_client_credentials(
    config: ServerConfig,
    client_id: str | None,
    client_secret: str | None,
    scope: str | None,
    audience: str | None,
) -> dict[Literal["access_token", "token_type", "expires_in", "scope"], str | int]:
    """Handle the client_credentials grant type.

    Performs the OAuth2 server to server client credentials flow.
    In this flow, a client can directly request an access token by providing its credentials, without any user involvement.

    Args:
        config: The server configuration.
        client_id: The client id provided in the request body. Required. It is only nullable for error handling purposes.
        client_secret: The client secret provided in the request body. Required. It is only nullable for error handling purposes.
        scope: The *space separated* requested scopes provided in the request body.
        audience: The requested audience provided in the request body.

    Returns:
        dict: The typical client credentials flow response data with "access_token", "token_type" and "expires_in" fields.

    Raises:
        InvalidClientException: If client authentication fails due to missing or invalid credentials.
        InvalidScopeException: If the client requests scopes that are not allowed for it.
        InvalidAudienceException: If the client requests an audience that is not allowed for it.
        OAuthServerErrorException: If there is an unexpected error during token creation.
    """
    if not client_id or not client_secret:
        raise InvalidRequestException(
            "Client authentication failed: missing credentials",
        )
    try:
        effective_client_secret_bytes = base64.b64decode(client_secret, validate=True)
    except Exception:
        raise InvalidRequestException(
            "Client authentication failed: invalid base64 encoding in secret",
        )

    client = get_client(config.db_path, client_id=client_id)
    if not client:
        raise InvalidClientException("Client authentication failed")

    if not client.verify_client_secret(effective_client_secret_bytes):
        raise InvalidClientException("Client authentication failed")

    requested_scopes: list[str] = []
    if scope:
        requested_scopes = scope.split()
        allowed_scopes = client.get_scopes_list()
        invalid_scopes = [
            scope for scope in requested_scopes if scope not in allowed_scopes
        ]
        if invalid_scopes:
            logger.warning(
                "Client %s requested invalid scopes: %s",
                client_id,
                ", ".join(invalid_scopes),
            )
            raise InvalidScopeException("Requested scopes not allowed for this client")

    if audience:
        allowed_audiences = client.get_audiences_list()
        if audience not in allowed_audiences:
            raise InvalidAudienceException(
                f"Requested audience not allowed for this client: {audience}"
            )

    try:
        access_token = create_access_token_for_client(
            config,
            client,
            scopes=requested_scopes if requested_scopes else None,
            audience=audience,
        )
        touch_client_last_used(config.db_path, client_id)
        logger.info(
            "Issued token for client: %s (algorithm: %s)",
            client_id,
            client.algorithm,
        )
    except Exception as e:
        logger.error("Failed to create token for client %s: %s", client_id, e)
        raise OAuthServerErrorException("Failed to create access token")

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        # TODO: replace by config env variable
        "expires_in": 3600,
        **({"scope": scope} if scope else {}),
    }
