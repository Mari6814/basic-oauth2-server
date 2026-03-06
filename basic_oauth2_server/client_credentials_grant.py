"""Handle the client_credentials grant type."""

import logging
import base64

from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasicCredentials


from .config import ServerConfig
from .exceptions import (
    InvalidAudienceException,
    InvalidClientException,
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
    basic_credentials: HTTPBasicCredentials | None,
) -> JSONResponse:
    """Handle the client_credentials grant type.

    Performs the OAuth2 server to server client credentials flow.
    In this flow, a client can directly request an access token by providing its credentials, without any user involvement.

    Args:
        config: The server configuration.
        client_id: The client id provided in the request body.
        client_secret: The client secret provided in the request body.
        scope: The *space separated* requested scopes provided in the request body.
        audience: The requested audience provided in the request body.
        basic_credentials: The client credentials provided in the Authorization header using HTTP Basic authentication. They also serve as client_id and client_secret, but are provided in a different way.

    Returns:
        JSONResponse: The typical client credentials flow JSONResponse with "access_token", "token_type" and "expires_in" fields.

    Raises:
        InvalidClientException: If client authentication fails due to missing or invalid credentials.
        InvalidScopeException: If the client requests scopes that are not allowed for it.
        InvalidAudienceException: If the client requests an audience that is not allowed for it.
        OAuthServerErrorException: If there is an unexpected error during token creation.
    """
    if basic_credentials:
        effective_client_id = basic_credentials.username
        effective_client_secret = basic_credentials.password
    elif client_id and client_secret:
        effective_client_id, effective_client_secret = client_id, client_secret
    else:
        raise InvalidClientException(
            "Client authentication failed: missing credentials"
        )
    try:
        effective_client_secret_bytes = base64.b64decode(
            effective_client_secret, validate=True
        )
    except Exception:
        raise InvalidClientException(
            "Client authentication failed: invalid base64 encoding in secret",
        )

    client = get_client(config.db_path, effective_client_id)
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
                effective_client_id,
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
        touch_client_last_used(config.db_path, effective_client_id)
        logger.info(
            "Issued token for client: %s (algorithm: %s)",
            effective_client_id,
            client.algorithm,
        )
    except Exception as e:
        logger.error("Failed to create token for client %s: %s", effective_client_id, e)
        raise OAuthServerErrorException("Failed to create access token")

    response_data = {
        "access_token": access_token,
        "token_type": "Bearer",
        # TODO: replace by config env variable
        "expires_in": 3600,
    }
    if requested_scopes:
        response_data["scope"] = " ".join(requested_scopes)

    return JSONResponse(content=response_data)
