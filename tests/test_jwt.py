"""Tests for JWT signing."""

import base64
import json

import pytest
from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm

from basic_oauth2_server.access_token import create_access_token
from basic_oauth2_server.jwt import (
    create_jwt,
    get_algorithm,
    is_symmetric,
)


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration (test helper)."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def test_is_symmetric() -> None:
    """Test algorithm classification."""
    assert is_symmetric(SymmetricAlgorithm.HS256) is True
    assert is_symmetric(SymmetricAlgorithm.HS384) is True
    assert is_symmetric(SymmetricAlgorithm.HS512) is True
    assert is_symmetric(AsymmetricAlgorithm.RS256) is False
    assert is_symmetric(AsymmetricAlgorithm.EdDSA) is False


def test_get_algorithm() -> None:
    """Test algorithm string to enum conversion."""
    assert get_algorithm("HS256") is SymmetricAlgorithm.HS256
    assert get_algorithm("RS256") is AsymmetricAlgorithm.RS256
    assert get_algorithm("EdDSA") is AsymmetricAlgorithm.EdDSA
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        get_algorithm("UNKNOWN")


def test_create_jwt_hs256() -> None:
    """Test creating a JWT with HS256."""
    claims = {"sub": "test", "aud": "api"}
    secret = b"supersecretkey123"

    token = create_jwt(claims, SymmetricAlgorithm.HS256, secret=secret)

    # Verify structure
    parts = token.split(".")
    assert len(parts) == 3

    # Verify header
    header = json.loads(_b64url_decode(parts[0]))
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"

    # Verify payload
    payload = json.loads(_b64url_decode(parts[1]))
    assert payload["sub"] == "test"
    assert payload["aud"] == "api"


def test_create_jwt_requires_secret_for_hmac() -> None:
    """Test that HMAC algorithms require a secret."""
    with pytest.raises(ValueError, match="Secret required"):
        create_jwt({"sub": "test"}, SymmetricAlgorithm.HS256)


def test_create_jwt_requires_private_key_for_asymmetric() -> None:
    """Test that asymmetric algorithms require a private key."""
    with pytest.raises(ValueError, match="Private key required"):
        create_jwt({"sub": "test"}, AsymmetricAlgorithm.RS256)


def test_create_access_token() -> None:
    """Test creating an access token."""
    secret = b"testsecret"
    token = create_access_token(
        client_id="my-app",
        algorithm=SymmetricAlgorithm.HS256,
        secret=secret,
        scopes=["read", "write"],
        audience="https://api.example.com",
        expires_in=3600,
    )

    parts = token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))

    assert payload["sub"] == "my-app"
    assert payload["scope"] == "read write"
    assert payload["aud"] == "https://api.example.com"
    assert "iat" in payload
    assert "exp" in payload
    assert payload["exp"] - payload["iat"] == 3600
