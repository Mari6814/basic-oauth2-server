"""Handle the client_credentials grant type."""

import logging
from typing import Literal

from .db import ClientRepository, TokenRepository
from .exceptions import (
    InvalidAudienceException,
    InvalidClientException,
    InvalidScopeException,
    OAuthServerErrorException,
)

logger = logging.getLogger(__name__)


def handle_client_credentials(
    client_id: str | None,
    client_secret: str | None,
    scope: str | None,
    audience: str | None,
    client_repo: ClientRepository,
    token_repo: TokenRepository,
) -> dict[Literal["access_token", "token_type", "expires_in", "scope"], str | int]:
    """Handle the client_credentials grant type."""
    if not client_id or not client_secret:
        raise InvalidClientException(
            "Client authentication failed: missing credentials"
        )
    client = client_repo.get(client_id)
    if client is None or not client.verify_client_secret(client_secret):
        raise InvalidClientException("Client authentication failed")

    requested_scopes: list[str] = []
    if scope:
        requested_scopes = scope.split()
        allowed_scopes = client.get_scopes_list()
        invalid_scopes = [
            requested_scope
            for requested_scope in requested_scopes
            if requested_scope not in allowed_scopes
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
        access_token = token_repo.issue_access_token(
            client=client,
            subject=client.client_id,
            scopes=requested_scopes if requested_scopes else None,
            audience=audience,
        )
        client_repo.touch_last_used(client_id)
        logger.info(
            "Issued token for client: %s (algorithm: %s)",
            client_id,
            client.algorithm,
        )
    except Exception as exc:
        logger.error("Failed to create token for client %s: %s", client_id, exc)
        raise OAuthServerErrorException("Failed to create access token") from exc

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": token_repo.token_expires_in,
        **({"scope": scope} if scope else {}),
    }
