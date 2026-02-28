"""JWT signing implementation using jws_algorithms."""

import base64
import json
from typing import Any

from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm

type Algorithm = SymmetricAlgorithm | AsymmetricAlgorithm


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def get_algorithm(alg: str) -> Algorithm:
    """Convert an algorithm name string to a SymmetricAlgorithm or AsymmetricAlgorithm."""
    if alg.startswith("HS"):
        return SymmetricAlgorithm[alg]
    if alg in SymmetricAlgorithm.__members__:
        return SymmetricAlgorithm[alg]
    if alg in AsymmetricAlgorithm:
        return AsymmetricAlgorithm(alg)
    if alg in AsymmetricAlgorithm.__members__:
        return AsymmetricAlgorithm[alg]
    raise ValueError(f"Unsupported algorithm: {alg}")


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
