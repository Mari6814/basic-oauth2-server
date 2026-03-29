import logging
from typing import Literal
from urllib.parse import urlencode

import hashlib
import base64

from .token_service import create_access_token_for_client
from .exceptions import (
    InvalidAudienceException,
    InvalidClientException,
    InvalidRequestException,
    InvalidGrantException,
    InvalidScopeException,
)
from .config import ServerConfig
from .db import (
    create_authorization_code,
    get_authorization_code,
    mark_authorization_code_used,
    get_client,
    touch_client_last_used,
)

logger = logging.getLogger(__name__)


def handle_authorize(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: list[str] | None,
    audience: str | None,
    state: str,
    config: ServerConfig,
) -> dict[
    Literal[
        "type",
        "message",
        "user",
        "client_id",
        "title",
        "requested_scopes",
        "audience",
        "redirect_uri",
        "confirm_url",
    ],
    str | list[str] | None,
]:
    """OAuth2 consent page.

    The consent page is responsible for validating the authorization request,
    and displaying it to the user for confirmation. If the user confirms, they
    will be redirected to the confirmation endpoint that asks for authentication
    and then issues the authorization code to the client.

    Parameters:
        client_id: The client for which the authorization request is being made. If the user confirms, the owner of that client will receive the bearer token to access resources the user owns.
        redirect_uri: The url to send the authorization code to after the user confirms. Must match one of the redirect URIs registered for the client.
        code_challenge: The PKCE code challenge from the authorization request.
        code_challenge_method: The PKCE code challenge method: "S256", "S512", or "plain".
        scope: The scopes requested by the client, as a list of strings. Must be a subset of the scopes registered for the client.
        audience: Optional audience requested by the client. Must be one of the audiences registered for the client.
        state: PKCE state parameter
        config: The server config, used to access the database and app URL for generating the confirm URL.

    Returns:
        Props for the consent page, including the confirm URL that the consent page should have a POST form button to.
    """
    if code_challenge_method not in ("S256", "S512", "plain"):
        raise InvalidRequestException(
            "code_challenge_method must be S256, S512, or plain"
        )

    client = get_client(config.db_path, client_id)
    if not client:
        raise InvalidClientException("Invalid client")

    allowed_uris = client.get_redirect_uris_list()
    if not allowed_uris or redirect_uri not in allowed_uris:
        raise InvalidRequestException("redirect_uri not registered for this client")

    requested_scopes = scope if scope else []
    if requested_scopes:
        allowed_scopes = client.get_scopes_list()
        invalid = [s for s in requested_scopes if s not in allowed_scopes]
        if invalid:
            raise InvalidScopeException(f"Invalid scopes: {', '.join(invalid)}")

    if audience:
        allowed_audiences = client.get_audiences_list()
        if audience not in allowed_audiences:
            raise InvalidAudienceException(f"Invalid audience: {audience}")

    confirm_params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": state,
    }
    if scope:
        confirm_params["scope"] = " ".join(scope)
    if audience:
        confirm_params["audience"] = audience

    base_url = config.app_url or ""
    confirm_url = f"{base_url}/authorize/confirm?{urlencode(confirm_params)}"

    return {
        "type": "consent",
        "message": f"Application '{client.title}' is requesting access.",
        "client_id": client_id,
        "title": client.title,
        "requested_scopes": requested_scopes or [],
        "audience": audience,
        "redirect_uri": redirect_uri,
        "confirm_url": confirm_url,
    }


def handle_authorize_confirm(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: list[str] | None,
    audience: str | None,
    state: str,
    username: str,
    config: ServerConfig,
) -> str:
    """Handles flow after the user has authenticated and authorized the request

    Sets up the authorization code and redirects to the client with the code.
    """
    code = create_authorization_code(
        db_path=config.db_path,
        client_id=client_id,
        user_id=username,
        redirect_uri=redirect_uri,
        scope=" ".join(scope) if scope else None,
        audience=audience,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    redirect_params: dict[str, str] = {"code": code, "state": state}

    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
    logger.info(
        "Authorization code issued for client %s, user %s",
        client_id,
        username,
    )
    return redirect_url


def handle_authorization_code(
    config: ServerConfig,
    client_id: str | None,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> dict[Literal["access_token", "token_type", "expires_in", "scope"], str | int]:
    """Handle the authorization_code grant type with PKCE validation."""
    if not code:
        raise InvalidRequestException("Missing authorization code")
    if not client_id:
        raise InvalidRequestException("Missing client_id")
    if not code_verifier:
        raise InvalidRequestException("Missing code_verifier (PKCE required)")

    auth_code = get_authorization_code(config.db_path, code)
    if not auth_code:
        raise InvalidGrantException("Invalid or expired authorization code")

    if auth_code.client_id != client_id:
        raise InvalidGrantException("Client ID mismatch")

    if auth_code.redirect_uri and auth_code.redirect_uri != redirect_uri:
        raise InvalidGrantException("Redirect URI mismatch")

    if auth_code.code_challenge:
        if not _verify_pkce(
            code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
        ):
            raise InvalidGrantException("PKCE code_verifier validation failed")

    mark_authorization_code_used(config.db_path, code)

    client = get_client(config.db_path, client_id)
    if not client:
        raise InvalidClientException("Client not found")

    scopes = auth_code.scope.split() if auth_code.scope else None

    access_token = create_access_token_for_client(
        config,
        client,
        scopes=scopes,
        audience=auth_code.audience,
        subject=auth_code.user_id,
    )

    touch_client_last_used(config.db_path, client_id)
    logger.info(
        "Issued token via authorization_code for client: %s, user: %s",
        client_id,
        auth_code.user_id,
    )

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": config.token_expires_in,
        **({"scope": " ".join(scopes)} if scopes else {}),
    }


def _verify_pkce(
    code_verifier: str, code_challenge: str, code_challenge_method: str
) -> bool:
    """Verify a PKCE code_verifier against the stored code_challenge."""
    if code_challenge_method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return computed == code_challenge
    elif code_challenge_method == "S512":
        digest = hashlib.sha512(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return computed == code_challenge
    elif code_challenge_method == "plain":
        return code_verifier == code_challenge
    return False
