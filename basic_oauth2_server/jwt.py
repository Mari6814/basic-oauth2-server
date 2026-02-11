"""JWT signing implementation using jws_algorithms."""

import base64
import json
import time
from typing import Any

from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm

type Algorithm = SymmetricAlgorithm | AsymmetricAlgorithm


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def get_algorithm(alg: str) -> Algorithm:
    """Convert an algorithm name string to a SymmetricAlgorithm or AsymmetricAlgorithm."""
    symmetric_mapping = {
        "HS256": SymmetricAlgorithm.HS256,
        "HS384": SymmetricAlgorithm.HS384,
        "HS512": SymmetricAlgorithm.HS512,
    }
    asymmetric_mapping = {
        "RS256": AsymmetricAlgorithm.RS256,
        "RS384": AsymmetricAlgorithm.RS384,
        "RS512": AsymmetricAlgorithm.RS512,
        "ES256": AsymmetricAlgorithm.ES256,
        "ES384": AsymmetricAlgorithm.ES384,
        "ES512": AsymmetricAlgorithm.ES512,
        "EdDSA": AsymmetricAlgorithm.EdDSA,
        "Ed25519": AsymmetricAlgorithm.EdDSA,
    }
    if alg in symmetric_mapping:
        return symmetric_mapping[alg]
    if alg in asymmetric_mapping:
        return asymmetric_mapping[alg]
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
) -> str:
    """Create a signed JWT.

    Args:
        claims: The JWT claims (payload).
        algorithm: The signing algorithm.
        secret: The shared secret (for HMAC algorithms).
        private_key: The private key bytes (for asymmetric algorithms).
        kid: Optional key ID to include in the JWT header.

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
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())

    # Create signing input
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # Sign based on algorithm type
    if is_symmetric(algorithm):
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
