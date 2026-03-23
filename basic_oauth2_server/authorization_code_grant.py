import logging
from typing import Literal
from urllib.parse import urlencode

from datetime import datetime, timezone
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

DEFAULT_EXPIRES_IN = 3600


def handle_authorize(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: list[str] | None,
    audience: str | None,
    state: str | None,
    username: str,
    config: ServerConfig,
) -> dict[
    Literal[
        "type",
        "message",
        "user",
        "client_id",
        "requested_scopes",
        "audience",
        "redirect_uri",
        "confirm_url",
    ],
    str | list[str] | None,
]:
    """OAuth2 consent endpoint

    Handles the /authorize endpoint, which validates the request and returns the
    data required for the consent page, including a confirm URL that the user
    can click to confirm the authorization request and receive an authorization
    code.

    Parameters:
    - client_id: The client for which the authorization request is being made. If the user confirms, the owner of that client will receive the bearer token to access resources the user owns.
    - redirect_uri: The url to send the authorization code to after the user confirms. TODO: Must match the redirect URI registered for the client.
    - code_challenge: The PKCE code challenge from the authorization request.
    - code_challenge_method: The PKCE code challenge method, either "S256" or "plain". TODO: Allow "S512" as well.
    - scope: The scopes requested by the client, as a list of strings. Must be a subset of the scopes registered for the client.
    - audience: Optional audience requested by the client. Must be one of the audiences registered for the client.
    - state: PKCE state parameter
    - username: The user currently logged in. If the use the confirmation url the issuer of the authorization request will receive the access token.
    -

    Returns:
        A dict with the props required for a consent page
    """

    if code_challenge_method not in ("S256", "plain"):
        raise InvalidRequestException("code_challenge_method must be S256 or plain")

    client = get_client(config.db_path, client_id)
    if not client:
        raise InvalidClientException("Invalid client", status_code=400)

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

    # TODO: Implement a user (not client) authentication system

    # Build confirm link
    confirm_params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    if scope:
        confirm_params["scope"] = " ".join(scope)
    if audience:
        confirm_params["audience"] = audience
    if state:
        confirm_params["state"] = state

    base_url = config.app_url or ""
    confirm_url = f"{base_url}/authorize/confirm?{urlencode(confirm_params)}"

    return {
        "type": "consent",
        "message": f"Application '{client_id}' is requesting access.",
        "user": username,
        "client_id": client_id,
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
    state: str | None,
    user_username: str,
    user_password: str,
    config: ServerConfig,
) -> str:
    code = create_authorization_code(
        db_path=config.db_path,
        client_id=client_id,
        user_id=user_username,
        redirect_uri=redirect_uri,
        scope=" ".join(scope) if scope else None,
        audience=audience,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    redirect_params: dict[str, str] = {"code": code}
    if state:
        redirect_params["state"] = state

    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
    logger.info(
        "Authorization code issued for client %s, user %s",
        client_id,
        user_username,
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
        raise InvalidRequestException("Invalid authorization code")

    if auth_code.used:
        raise InvalidGrantException("Authorization code already used")

    if auth_code.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise InvalidGrantException("Authorization code expired")

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
        "expires_in": DEFAULT_EXPIRES_IN,
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
    # TODO: Add S512 and maybe have a enum for code_challenge_method
    elif code_challenge_method == "plain":
        return code_verifier == code_challenge
    return False
