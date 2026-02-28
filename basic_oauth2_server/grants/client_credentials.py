"""Implements a handler for the client credentials grant type."""

import base64
import logging
from collections.abc import Callable

from ..db import Client
from ..exceptions import OAuthError

logger = logging.getLogger(__name__)


def handle_client_credentials_grant(
    authorization_header: str | None,
    client_id: str | None,
    client_secret: str | None,
    scope: str | None,
    audience: str | None,
    expires_in: int,
    *,
    authenticate_client: Callable[[str, bytes], Client | None],
    create_token: Callable[[Client, list[str] | None, str | None], str],
    record_usage: Callable[[str], None],
) -> dict:
    """Handle a client credentials grant request.

    Args:
        authorization_header: The "Authorization" header from the request, or None.
            Basic Auth credentials take priority over form parameters.
        client_id: Client ID from the request body, or None.
        client_secret: Client secret from the request body, or None.
        scope: Optional space-separated scopes. Only scopes configured on the
            client are accepted.
        audience: Optional intended audience for the token. Only audiences
            configured on the client are accepted.
        expires_in: Token lifetime in seconds.
        authenticate_client: Looks up a client by ID and verifies the secret.
            Returns the Client if valid, None otherwise.
        create_token: Creates a signed access token for the given client.
        record_usage: Records that the client was used (e.g. updates last_used_at).

    Returns:
        A dict containing the access token response fields.

    Raises:
        OAuthError: If client authentication or validation fails.
    """
    effective_client_id, effective_client_secret = _extract_credentials(
        authorization_header, client_id, client_secret
    )

    try:
        effective_client_secret_bytes = base64.b64decode(
            effective_client_secret, validate=True
        )
    except Exception:
        raise OAuthError(
            "invalid_client",
            "Client authentication failed: invalid base64 encoding in secret",
            status_code=401,
        )

    client = authenticate_client(effective_client_id, effective_client_secret_bytes)
    if not client:
        raise OAuthError(
            "invalid_client",
            "Client authentication failed",
            status_code=401,
        )

    requested_scopes: list[str] = []
    if scope:
        requested_scopes = scope.split()
        invalid_scopes = client.validate_scopes(requested_scopes)
        if invalid_scopes:
            logger.warning(
                "Client %s requested invalid scopes: %s",
                effective_client_id,
                ", ".join(invalid_scopes),
            )
            raise OAuthError(
                "invalid_scope",
                "Requested scopes not allowed for this client",
                status_code=400,
            )

    if audience and not client.is_audience_allowed(audience):
        raise OAuthError(
            "invalid_audience",
            f"Requested audience not allowed for this client: {audience}",
            status_code=400,
        )

    access_token = create_token(
        client,
        requested_scopes if requested_scopes else None,
        audience,
    )

    record_usage(effective_client_id)
    logger.info(
        "Issued token for client: %s (algorithm: %s)",
        effective_client_id,
        client.algorithm,
    )

    response_data: dict = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }
    if requested_scopes:
        response_data["scope"] = " ".join(requested_scopes)

    return response_data


def _extract_credentials(
    authorization_header: str | None,
    client_id: str | None,
    client_secret: str | None,
) -> tuple[str, str]:
    """Extract client credentials from Basic auth header or form params.

    Basic Auth header takes priority over form parameters.
    """
    if authorization_header and authorization_header.lower().startswith("basic "):
        try:
            encoded = authorization_header.split(" ", 1)[1]
            decoded = base64.b64decode(encoded).decode("utf-8")
            basic_id, basic_secret = decoded.split(":", 1)
            return basic_id, basic_secret
        except Exception:
            raise OAuthError(
                "invalid_client",
                "Client authentication failed: malformed Authorization header",
                status_code=401,
            )

    if client_id and client_secret:
        return client_id, client_secret

    raise OAuthError(
        "invalid_client",
        "Client authentication failed: missing credentials",
        status_code=401,
    )
