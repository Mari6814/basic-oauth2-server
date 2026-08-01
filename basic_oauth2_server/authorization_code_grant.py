"""Authorization code and refresh token grant handlers."""

import base64
import hashlib
import logging
from typing import Literal
from urllib.parse import urlencode

from basic_oauth2_server.consent_token import create_consent_token
from basic_oauth2_server.config import ServerConfig

from .db import ClientRepository, TokenRepository
from .exceptions import (
    AuthorizationRedirectException,
    InvalidClientException,
    InvalidGrantException,
    InvalidRequestException,
)

logger = logging.getLogger(__name__)


def handle_authorize(
    authorized_username: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: list[str] | None,
    audience: str | None,
    state: str,
    config: ServerConfig,
    client_repo: ClientRepository,
) -> dict[
    Literal[
        "type",
        "message",
        "client_id",
        "title",
        "requested_scopes",
        "audience",
        "redirect_uri",
        "consent_token",
        "user",
    ],
    str | list[str] | None,
]:
    """Validate the authorization request and return consent page data.

    The consent page is responsible for validating the authorization request
    and presenting it to the authenticated user for confirmation.

    Parameters:
        authorized_username: The already-authenticated user's username.
        client_id: The client requesting access. If the user confirms, this
            client receives the authorization code to exchange for tokens.
        redirect_uri: Where to send the authorization code after confirmation.
            Must match one of the redirect URIs registered for the client.
        code_challenge: base64url(SHA-256(code_verifier)) sent by the client at authorization time.
        code_challenge_method: Hashing method used for the code challenge. Only "S256" is supported.
        scope: Scopes requested by the client. Must be a subset of the
            scopes registered for the client.
        audience: Optional audience requested by the client. Must be one of
            the audiences registered for the client.
        state: Opaque value from the client used to prevent CSRF and correlate
            the authorization response with the original request.
        config: Server configuration, used for the app URL and signing key.
        client_repo: Client persistence operations.

    Returns:
        Consent page data including the signed consent token the user must
        POST to /authorize/confirm to complete the flow.
    """
    if code_challenge_method != "S256":
        raise InvalidRequestException("code_challenge_method must be S256")

    client = client_repo.get(client_id)
    if client is None:
        raise InvalidClientException("Invalid client")

    allowed_uris = client.get_redirect_uris_list()
    if not allowed_uris or redirect_uri not in allowed_uris:
        raise InvalidRequestException("redirect_uri not registered for this client")

    requested_scopes = scope if scope else []
    if requested_scopes:
        allowed_scopes = client.get_scopes_list()
        invalid_scopes = [
            requested_scope
            for requested_scope in requested_scopes
            if requested_scope not in allowed_scopes
        ]
        if invalid_scopes:
            raise AuthorizationRedirectException(
                redirect_uri=redirect_uri,
                error="invalid_scope",
                description=f"Invalid scopes: {', '.join(invalid_scopes)}",
                state=state,
            )

    if audience:
        allowed_audiences = client.get_audiences_list()
        if audience not in allowed_audiences:
            raise AuthorizationRedirectException(
                redirect_uri=redirect_uri,
                error="invalid_request",
                description=f"Invalid audience: {audience}",
                state=state,
            )

    consent_token = create_consent_token(
        username=authorized_username,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        state=state,
        scope=" ".join(scope) if scope else None,
        audience=audience,
        config=config,
    )

    return {
        "type": "consent",
        "message": f"Application '{client.title}' is requesting access.",
        "client_id": client_id,
        "title": client.title,
        "requested_scopes": requested_scopes or [],
        "audience": audience,
        "redirect_uri": redirect_uri,
        "consent_token": consent_token,
        "user": authorized_username,
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
    consent_jti: str,
    token_repo: TokenRepository,
) -> str:
    """Create an authorization code and redirect to the client.

    Assumes the user has authenticated, reviewed the consent page, and
    confirmed the request. Stores the authorization code and returns the
    redirect URL with the code and state attached.
    TODO: Rewrite documentation here. Clarify that `username` is meant to be assumed the authenticated user without implying that anything unsafe is happening here... Also, probably need to refactor consent token concept? The code is not robust enough for me to guarantee that it actually proves anything.
    """
    code = token_repo.create_authorization_code(
        client_id=client_id,
        user_id=username,
        redirect_uri=redirect_uri,
        scope=" ".join(scope) if scope else None,
        audience=audience,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        consent_jti=consent_jti,
        expires_in=600,
    )
    redirect_url = f"{redirect_uri}?{urlencode({'code': code, 'state': state})}"
    logger.info(
        "Authorization code issued for client %s, user %s",
        client_id,
        username,
    )
    return redirect_url


def handle_authorization_code(
    client_id: str,
    client_secret: str,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
    client_repo: ClientRepository,
    token_repo: TokenRepository,
) -> dict[
    Literal["access_token", "token_type", "expires_in", "refresh_token", "scope"],
    str | int,
]:
    """Handle the authorization_code grant type with PKCE validation.

    After authenticating the client, the client proves it initiated the
    authorization request by presenting the authorization code and the
    code_verifier whose SHA-256 hash matches the stored code_challenge.

    Args:
        client_id: OAuth client identifier.
        client_secret: Client secret for authentication.
        code: The authorization code issued by /authorize.
        redirect_uri: Must match the redirect_uri used when the code was issued.
        code_verifier: Raw random string whose base64url(SHA-256) must equal the stored code_challenge.
        client_repo: Client persistence operations.
        token_repo: Token persistence and issuance operations.

    Returns:
        OAuth token response containing access_token, token_type, expires_in,
        refresh_token, and optionally scope.
    """
    if not code:
        raise InvalidRequestException("Missing authorization code")
    if not code_verifier:
        raise InvalidRequestException("Missing PKCE code_verifier")

    client = client_repo.get(client_id)
    if client is None:
        raise InvalidClientException("Client not found")
    if not client.verify_client_secret(client_secret):
        raise InvalidClientException("Client authentication failed")

    auth_code = token_repo.consume_authorization_code(code)
    if auth_code is None:
        raise InvalidGrantException("Invalid or expired authorization code")
    if auth_code.client_id != client_id:
        raise InvalidGrantException("Client ID mismatch")
    if auth_code.redirect_uri and auth_code.redirect_uri != redirect_uri:
        raise InvalidGrantException("Redirect URI mismatch")
    if not auth_code.code_challenge or not _verify_pkce(
        code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
    ):
        raise InvalidGrantException("PKCE code_verifier validation failed")

    user_id = auth_code.user_id
    auth_code_audience = auth_code.audience
    scopes = auth_code.scope.split() if auth_code.scope else None
    access_token = token_repo.issue_access_token(
        client=client,
        subject=user_id,
        scopes=scopes,
        audience=auth_code_audience,
    )
    refresh_token = token_repo.issue_refresh_token(
        client=client,
        user_id=user_id,
        scopes=scopes,
        audience=auth_code_audience,
    )

    client_repo.touch_last_used(client_id)
    token_repo.prune_authorization_codes()
    token_repo.prune_refresh_tokens()
    logger.info(
        "Issued token via authorization_code for client: %s, user: %s",
        client_id,
        user_id,
    )
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": token_repo.token_expires_in,
        "refresh_token": refresh_token,
        **({"scope": " ".join(scopes)} if scopes else {}),
    }


def handle_refresh_token(
    client_id: str,
    client_secret: str,
    refresh_token: str | None,
    client_repo: ClientRepository,
    token_repo: TokenRepository,
) -> dict[
    Literal["access_token", "token_type", "expires_in", "refresh_token", "scope"],
    str | int,
]:
    """Handle the refresh_token grant type.

    Consumes the presented refresh token and issues a fresh access token and a new refresh token.

    Args:
        client_id: ID of the client that the refresh token belongs to.
        client_secret: Secret value to authenticate the client.
        refresh_token: The opaque refresh token to exchange.
        client_repo: Client persistence operations.
        token_repo: Token persistence and issuance operations.

    Returns:
        OAuth token response containing access_token, token_type, expires_in,
        refresh_token, and optionally scope.

    Raises:
        InvalidRequestException: If refresh_token parameter is missing.
        InvalidClientException: If client authentication fails.
        InvalidGrantException: If the refresh token is invalid, expired, or
            bound to a different client.
    """
    if not refresh_token:
        raise InvalidRequestException("Missing refresh_token")

    client = client_repo.get(client_id)
    if client is None:
        raise InvalidClientException("Client not found")
    if not client.verify_client_secret(client_secret):
        raise InvalidClientException("Client authentication failed")

    persisted_refresh_token = token_repo.consume_refresh_token(refresh_token)
    if persisted_refresh_token is None:
        raise InvalidGrantException("Invalid or expired refresh token")
    if persisted_refresh_token.client_id != client_id:
        raise InvalidGrantException("Invalid or expired refresh token")

    scopes = (
        persisted_refresh_token.scope.split() if persisted_refresh_token.scope else None
    )
    access_token = token_repo.issue_access_token(
        client=client,
        subject=persisted_refresh_token.user_id,
        scopes=scopes,
        audience=persisted_refresh_token.audience,
    )
    rotated_refresh_token = token_repo.issue_refresh_token(
        client=client,
        user_id=persisted_refresh_token.user_id,
        scopes=scopes,
        audience=persisted_refresh_token.audience,
    )

    client_repo.touch_last_used(client_id)
    token_repo.prune_refresh_tokens()
    logger.info(
        "Issued token via refresh_token for client: %s, user: %s",
        client_id,
        persisted_refresh_token.user_id,
    )
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": token_repo.token_expires_in,
        "refresh_token": rotated_refresh_token,
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
    return False
