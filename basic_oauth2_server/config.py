"""Configuration management for the OAuth server."""

import os
from typing import Self
from dataclasses import dataclass

from jws_algorithms import AsymmetricAlgorithm


@dataclass
class ServerConfig:
    """Configuration for the OAuth server."""

    host: str = "localhost"
    port: int = 8080
    db_path: str = "./oauth.db"
    app_url: str | None = None
    token_expires_in: int = 3600
    rsa_private_key: str | None = None
    rsa_key_id: str | None = None
    ec_p256_private_key: str | None = None
    ec_p256_key_id: str | None = None
    ec_p384_private_key: str | None = None
    ec_p384_key_id: str | None = None
    ec_p521_private_key: str | None = None
    ec_p521_key_id: str | None = None
    eddsa_private_key: str | None = None
    eddsa_key_id: str | None = None

    @classmethod
    def from_env(cls) -> Self:
        """Create configuration from environment variables."""
        return cls(
            host=os.environ.get("OAUTH_HOST", "localhost"),
            port=int(os.environ.get("OAUTH_PORT", "8080")),
            db_path=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
            app_url=os.environ.get("APP_URL"),
            token_expires_in=int(
                os.environ.get("OAUTH_ACCESS_TOKEN_EXPIRES_IN", "3600")
            ),
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

    def get_private_key_for_algorithm(
        self, algorithm: AsymmetricAlgorithm
    ) -> tuple[str | None, str | None]:
        """Get the appropriate private key and key ID for the given algorithm."""
        match algorithm:
            case (
                AsymmetricAlgorithm.RS256
                | AsymmetricAlgorithm.RS384
                | AsymmetricAlgorithm.RS512
                | AsymmetricAlgorithm.PS256
                | AsymmetricAlgorithm.PS384
                | AsymmetricAlgorithm.PS512
            ):
                return self.rsa_private_key, self.rsa_key_id
            case AsymmetricAlgorithm.ES256:
                return self.ec_p256_private_key, self.ec_p256_key_id
            case AsymmetricAlgorithm.ES384:
                return self.ec_p384_private_key, self.ec_p384_key_id
            case AsymmetricAlgorithm.ES512:
                return self.ec_p521_private_key, self.ec_p521_key_id
            case AsymmetricAlgorithm.EdDSA:
                return self.eddsa_private_key, self.eddsa_key_id
            case _:
                return None, None


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
