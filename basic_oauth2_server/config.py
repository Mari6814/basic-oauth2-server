"""Configuration management for the OAuth server."""

import os
from typing import Self
from dataclasses import dataclass
from functools import cache
from jws_algorithms import AsymmetricAlgorithm
from .utils import decode_prefixed_utf8


@dataclass(frozen=True)
class ServerConfig:
    """Configuration for the OAuth server."""

    host: str = "localhost"
    port: int = 8080
    db_path: str = "./oauth.db"
    app_url: str | None = None  # Issuer URL for JWT 'iss' claim
    # Private keys for asymmetric algorithms (each algorithm family needs its own key)
    rsa_private_key: str | None = None  # For RS256, RS384, RS512, PS256, PS384, PS512
    ec_p256_private_key: str | None = None  # For ES256
    ec_p384_private_key: str | None = None  # For ES384
    ec_p521_private_key: str | None = None  # For ES512
    eddsa_private_key: str | None = None  # For EdDSA
    # These will be added to the JWT 'kid' header and the jwks.json 'kid' field if set
    rsa_key_id: str | None = None
    ec_p256_key_id: str | None = None
    ec_p384_key_id: str | None = None
    ec_p521_key_id: str | None = None
    eddsa_key_id: str | None = None
    # TODO: Add token expiry env variable

    @cache
    def load_private_key(self, algorithm: AsymmetricAlgorithm) -> bytes:
        """Load the appropriate private key for the given algorithm.

        Either parses the raw key from this config or if a file is being referenced,
        loads the file content and returns it. Caches the result per algorithm to avoid repeated file reads.

        Args:
            algorithm: The signing algorithm for which to load the private key.

        Returns:
            The private key bytes to be used for signing JWTs with the given algorithm.

        Raises:
            ValueError: If no key is configured for the given algorithm or if the file cannot be read.
        """
        match algorithm:
            case (
                AsymmetricAlgorithm.RS256
                | AsymmetricAlgorithm.RS384
                | AsymmetricAlgorithm.RS512
                | AsymmetricAlgorithm.PS256
                | AsymmetricAlgorithm.PS384
                | AsymmetricAlgorithm.PS512
            ):
                key_str = self.rsa_private_key
            case AsymmetricAlgorithm.ES256:
                key_str = self.ec_p256_private_key
            case AsymmetricAlgorithm.ES384:
                key_str = self.ec_p384_private_key
            case AsymmetricAlgorithm.ES512:
                key_str = self.ec_p521_private_key
            case AsymmetricAlgorithm.EdDSA:
                key_str = self.eddsa_private_key
            case _:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

        if not key_str:
            raise ValueError(
                f"No private key configured for {algorithm}. "
                f"Set the appropriate --*-private-key option or environment variable."
            )
        return decode_prefixed_utf8(key_str, allow_from_file=True)

    @classmethod
    def from_env(cls) -> Self:
        """Create configuration from environment variables."""
        return cls(
            host=os.environ.get("OAUTH_HOST", "localhost"),
            port=int(os.environ.get("OAUTH_PORT", "8080")),
            db_path=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
            app_url=os.environ.get("APP_URL"),
            rsa_private_key=os.environ.get("OAUTH_RSA_PRIVATE_KEY"),
            ec_p256_private_key=os.environ.get("OAUTH_EC_P256_PRIVATE_KEY"),
            ec_p384_private_key=os.environ.get("OAUTH_EC_P384_PRIVATE_KEY"),
            ec_p521_private_key=os.environ.get("OAUTH_EC_P521_PRIVATE_KEY"),
            eddsa_private_key=os.environ.get("OAUTH_EDDSA_PRIVATE_KEY"),
            rsa_key_id=os.environ.get("OAUTH_RSA_KEY_ID"),
            ec_p256_key_id=os.environ.get("OAUTH_EC_P256_KEY_ID"),
            ec_p384_key_id=os.environ.get("OAUTH_EC_P384_KEY_ID"),
            ec_p521_key_id=os.environ.get("OAUTH_EC_P521_KEY_ID"),
            eddsa_key_id=os.environ.get("OAUTH_EDDSA_KEY_ID"),
        )


@dataclass
class AdminConfig:
    """Configuration for the admin dashboard."""

    app_url: str | None = None
    host: str = "localhost"
    port: int = 8081
    db_path: str = "./oauth.db"

    @classmethod
    def from_env(cls) -> Self:
        """Create configuration from environment variables."""
        return cls(
            app_url=os.environ.get("APP_URL"),
            host=os.environ.get("OAUTH_ADMIN_HOST", "localhost"),
            port=int(os.environ.get("OAUTH_ADMIN_PORT", "8081")),
            db_path=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
        )


def get_app_key() -> bytes:
    """Get the APP_KEY for encryption, raising if not set."""
    key = os.environ.get("APP_KEY")
    if not key:
        raise ValueError("APP_KEY environment variable is required")
    # Handle base64-encoded keys
    import base64

    try:
        return base64.b64decode(key)
    except Exception:
        # Treat as raw string if not valid base64
        return key.encode("utf-8")
