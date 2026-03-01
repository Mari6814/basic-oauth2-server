"""JWKS (JSON Web Key Set) generation from configured private keys."""

import logging
from typing import Any

from jws_algorithms import AsymmetricAlgorithm

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.utils import decode_prefixed_utf8

logger = logging.getLogger(__name__)


def _try_add_jwk(
    keys: list[dict[str, Any]],
    algorithm: AsymmetricAlgorithm,
    private_key_str: str,
    kid: str | None = None,
    *,
    include_alg: bool = True,
) -> None:
    """Parse a private key and append its public JWK to the list."""
    try:
        private_key_bytes = decode_prefixed_utf8(private_key_str)
        jwk = dict(algorithm.to_jwk(private_key_bytes))
        if not include_alg:
            jwk.pop("alg", None)
        if kid:
            jwk["kid"] = kid
        keys.append(jwk)
    except Exception:
        logger.exception("Failed to convert %s private key to JWK", algorithm.name)


def build_jwks(config: ServerConfig) -> dict[str, list[dict[str, Any]]]:
    """Build a JWKS document from the server's configured private keys.

    Checks each asymmetric private key config field explicitly, extracts the
    public key component as a JWK, and returns the standard JWKS wrapper.

    Returns:
        A dict of the form {"keys": [...]}, where each entry is a JWK
        representing the public key. The ``kid`` field is included when
        a key ID is configured.
    """
    keys: list[dict[str, Any]] = []

    if config.rsa_private_key:
        _try_add_jwk(
            keys,
            AsymmetricAlgorithm.RS256,
            config.rsa_private_key,
            config.rsa_key_id,
            include_alg=False,
        )

    if config.ec_p256_private_key:
        _try_add_jwk(
            keys,
            AsymmetricAlgorithm.ES256,
            config.ec_p256_private_key,
            config.ec_p256_key_id,
        )

    if config.ec_p384_private_key:
        _try_add_jwk(
            keys,
            AsymmetricAlgorithm.ES384,
            config.ec_p384_private_key,
            config.ec_p384_key_id,
        )

    if config.ec_p521_private_key:
        _try_add_jwk(
            keys,
            AsymmetricAlgorithm.ES512,
            config.ec_p521_private_key,
            config.ec_p521_key_id,
        )

    if config.eddsa_private_key:
        _try_add_jwk(
            keys,
            AsymmetricAlgorithm.EdDSA,
            config.eddsa_private_key,
            config.eddsa_key_id,
        )

    return {"keys": keys}
