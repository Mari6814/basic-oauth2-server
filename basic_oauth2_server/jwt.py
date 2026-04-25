"""JWT signing implementation using jws_algorithms."""

import base64
import json
import time
from typing import Any
import uuid

from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm

type Algorithm = SymmetricAlgorithm | AsymmetricAlgorithm


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def get_algorithm(alg: str) -> Algorithm:
    """Convert an algorithm name string to a SymmetricAlgorithm or AsymmetricAlgorithm."""
    if alg.startswith("HS"):
        return SymmetricAlgorithm[alg]
    if alg in SymmetricAlgorithm.__members__:  # pragma: no cover
        return SymmetricAlgorithm[alg]
    if alg in AsymmetricAlgorithm:
        return AsymmetricAlgorithm(alg)
    if alg in AsymmetricAlgorithm.__members__:
        return AsymmetricAlgorithm[alg]
    raise ValueError(f"Unsupported algorithm: {alg}")


def is_symmetric(algorithm: Algorithm) -> bool:
    """Check if an algorithm enum is symmetric (HMAC-based)."""
    return isinstance(algorithm, SymmetricAlgorithm)


def create_jwt(
    claims: dict[str, Any],
    algorithm: Algorithm,
    secret: bytes | None = None,
    private_key: bytes | None = None,
    kid: str | None = None,
    expires_in: int | None = None,
) -> str:
    """Create a signed JWT.

    Args:
        claims: The JWT claims (payload).
        algorithm: The signing algorithm.
        secret: The shared secret (for HMAC algorithms).
        private_key: The private key bytes (for asymmetric algorithms).
        kid: Optional key ID to include in the JWT header.
        expires_in: If set, automatically sets the 'exp' claim to current time + expires_in seconds.

    Returns:
        The signed JWT as a string.

    Raises:
        ValueError: If required key material is missing.
    """
    # Create header
    header: dict[str, str] = {"alg": algorithm.name, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())

    # Create payload
    if expires_in is not None:
        claims["exp"] = int(time.time()) + expires_in
    if "iat" not in claims:
        claims["iat"] = int(time.time())
    if "jti" not in claims:
        claims["jti"] = str(uuid.uuid4())
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())

    # Create signing input
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # Sign based on algorithm type
    if isinstance(algorithm, SymmetricAlgorithm):
        if not secret:
            raise ValueError(f"Secret required for {algorithm.name}")
        signature = algorithm.sign(secret, signing_input)
    else:
        if not private_key:
            raise ValueError(f"Private key required for {algorithm.name}")
        signature = algorithm.sign(private_key, signing_input)

    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def create_access_token(
    subject: str,
    algorithm: Algorithm,
    secret: bytes | None = None,
    private_key: bytes | None = None,
    scopes: list[str] | None = None,
    audience: str | None = None,
    expires_in: int = 3600,
    kid: str | None = None,
    issuer: str | None = None,
    client_id: str | None = None,
) -> str:
    """Create an OAuth access token JWT.

    Args:
        subject: Will be added as the 'sub' claim. Usually the client id or user id the token represents.
        algorithm: The signing algorithm.
        secret: The shared secret (for HMAC).
        private_key: The private key (for asymmetric).
        scopes: List of granted scopes.
        audience: The token audience.
        expires_in: Token lifetime in seconds.
        kid: Optional key ID to include in the JWT header.
        issuer: Optional issuer URL for the 'iss' claim.
        client_id: The optional client_id used in authorization code flows where the subject is the user, but we also want to additionally include the client_id in the token for introspection purposes.

    Returns:
        The signed JWT access token.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
    }

    if issuer:
        claims["iss"] = issuer

    if scopes:
        claims["scope"] = " ".join(scopes)

    if audience:
        claims["aud"] = audience

    if client_id:
        # Keycloak convention for "authorized party" claim, dunno...
        claims["azp"] = client_id
        # Also include client_id explicitly for introspection and clarity
        claims["client_id"] = client_id

    return create_jwt(
        claims, algorithm, secret=secret, private_key=private_key, kid=kid
    )
