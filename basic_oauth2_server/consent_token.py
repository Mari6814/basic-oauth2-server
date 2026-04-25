"""Consent token creation and verification for the authorization code flow.

We use JWT as the consent token to bundle together, in a way that does not allow
tempering by the client, all the parameters from the authorization request that we
the user then can confirm or deny.
"""

import base64
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from jws_algorithms import SymmetricAlgorithm

from .config import ServerConfig, get_app_key
from .exceptions import InvalidRequestException
from .jwt import create_jwt

CONSENT_TOKEN_EXPIRES_IN = 300
ALGORITHM = SymmetricAlgorithm.HS512


@dataclass(frozen=True)
class ConsentClaims:
    """The object that we expect the consent token to decode into after verification."""

    username: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    state: str
    scope: str | None
    audience: str | None
    jti: str
    exp: int


def create_consent_token(
    *,
    username: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str | None = None,
    audience: str | None = None,
    expires_in: int = CONSENT_TOKEN_EXPIRES_IN,
    config: ServerConfig,
) -> str:
    """Create a signed consent JWT encoding the full authorization request.

    This token is used to carry all necessary information from the consent page
    back to to the confirmation page, while preventing tampering by the client.

    Args:
        username: The authenticated user's username.
        client_id: OAuth client identifier.
        redirect_uri: The redirect URI for the authorization code.
        code_challenge: PKCE code challenge.
        code_challenge_method: PKCE method.
        state: PKCE/CSRF state parameter.
        scope: Space-separated scope string, or None.
        audience: Requested audience, or None.
        expires_in: Token lifetime in seconds.
        config: The current server environment required to get some parameters required for the token claims and signing.

    Returns:
        A signed JWT string.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": username,
        "iat": now,
        "exp": now + expires_in,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": state,
        "aud": config.app_url,
        "iss": config.app_url,
    }
    if scope is not None:
        claims["scope"] = scope
    if audience is not None:
        claims["audience"] = audience

    return create_jwt(
        claims=claims,
        algorithm=ALGORITHM,
        secret=get_app_key(),
    )


def verify_consent_token(token: str, config: ServerConfig) -> ConsentClaims:
    """Verify and decode a consent JWT.

    Does NOT consume the JTI. The caller is responsible for calling
    ``consume_consent_jti`` from ``db`` after all other checks pass
    (e.g. user-mismatch checks) to prevent replay without allowing an
    adversary to invalidate a legitimate user's pending token.

    Args:
        token: The JWT string to verify.
        config: The server configuration containing parameters required to verify the token.

    Returns:
        A ConsentClaims dataclass with the decoded claims, including ``jti``
        and ``exp`` so the caller can record the token as used.

    Raises:
        InvalidRequestException: If the token is malformed, has an invalid
            signature, or has expired.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise InvalidRequestException("Invalid consent token")

    try:
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8")
        claims: dict[str, Any] = json.loads(payload_bytes)
    except Exception:
        raise InvalidRequestException("Invalid consent token")

    key = get_app_key()
    if not ALGORITHM.verify(key, f"{header_b64}.{payload_b64}", sig):
        raise InvalidRequestException("Invalid consent token signature")

    if config.app_url is not None:
        if "iss" not in claims or claims["iss"] != config.app_url:
            raise InvalidRequestException("Invalid consent token issuer")
        if "aud" not in claims or claims["aud"] != config.app_url:
            raise InvalidRequestException("Invalid consent token audience")
    if claims.get("exp", 0) < int(time.time()):
        raise InvalidRequestException("Consent token has expired")
    if claims.get("iat", 0) > int(time.time()):
        raise InvalidRequestException("Consent token issued in the future")

    jti = claims.get("jti")
    if not jti:
        raise InvalidRequestException("Consent token missing jti claim")

    try:
        return ConsentClaims(
            username=claims["sub"],
            client_id=claims["client_id"],
            redirect_uri=claims["redirect_uri"],
            code_challenge=claims["code_challenge"],
            code_challenge_method=claims["code_challenge_method"],
            state=claims["state"],
            scope=claims.get("scope"),
            audience=claims.get("audience"),
            jti=jti,
            exp=int(claims.get("exp", 0)),
        )
    except KeyError as exc:
        raise InvalidRequestException(f"Consent token missing claim: {exc}") from exc
