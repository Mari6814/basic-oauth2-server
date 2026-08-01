"""Tests for JWT signing."""

import base64
import json
import time

import pytest
from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm

from basic_oauth2_server.jwt import (
    create_access_token,
    create_jwt,
    get_algorithm,
    is_symmetric,
    verify_jwt,
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
        subject="my-app",
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


def test_create_jwt_with_expires_in() -> None:
    """Test that create_jwt sets exp when expires_in is provided."""
    before = int(time.time())
    token = create_jwt(
        {"sub": "test"},
        SymmetricAlgorithm.HS256,
        secret=b"secret",
        expires_in=600,
    )
    parts = token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))
    assert "exp" in payload
    assert payload["exp"] >= before + 600


def test_create_jwt_does_not_mutate_claims() -> None:
    """Test that create_jwt does not mutate the caller's claims dict."""
    original = {"sub": "client1"}

    create_jwt(original, SymmetricAlgorithm.HS256, secret=b"secret")

    assert original == {"sub": "client1"}


def test_create_access_token_with_single_audience() -> None:
    """Single string audience is set as a plain string in the aud claim."""
    token = create_access_token(
        subject="user1",
        algorithm=SymmetricAlgorithm.HS256,
        secret=b"secret",
        audience="https://api.example.com",
    )
    payload = json.loads(_b64url_decode(token.split(".")[1]))
    assert payload["aud"] == "https://api.example.com"


def test_create_access_token_with_list_audience() -> None:
    """List audience is set as a JSON array in the aud claim."""
    audiences = ["https://api.example.com", "https://other.example.com"]
    token = create_access_token(
        subject="user1",
        algorithm=SymmetricAlgorithm.HS256,
        secret=b"secret",
        audience=audiences,
    )
    payload = json.loads(_b64url_decode(token.split(".")[1]))
    assert payload["aud"] == audiences


def test_create_access_token_without_audience() -> None:
    """No aud claim is set when audience is None."""
    token = create_access_token(
        subject="user1",
        algorithm=SymmetricAlgorithm.HS256,
        secret=b"secret",
        audience=None,
    )
    payload = json.loads(_b64url_decode(token.split(".")[1]))
    assert "aud" not in payload


def test_verify_jwt_rejects_expired_token() -> None:
    """Expired tokens are rejected."""
    token = create_jwt(
        {"sub": "test", "exp": int(time.time()) - 60},
        SymmetricAlgorithm.HS256,
        secret=b"secret",
    )

    assert (
        verify_jwt(
            token,
            algorithm=SymmetricAlgorithm.HS256,
            secret=b"secret",
            public_key=None,
        )
        is None
    )


def test_verify_jwt_rejects_future_nbf() -> None:
    """Tokens before their not-before time are rejected."""
    token = create_jwt(
        {"sub": "test", "nbf": int(time.time()) + 60},
        SymmetricAlgorithm.HS256,
        secret=b"secret",
    )

    assert (
        verify_jwt(
            token,
            algorithm=SymmetricAlgorithm.HS256,
            secret=b"secret",
            public_key=None,
        )
        is None
    )


def test_verify_jwt_accepts_past_nbf() -> None:
    """Tokens after their not-before time are accepted."""
    token = create_jwt(
        {"sub": "test", "nbf": int(time.time()) - 60},
        SymmetricAlgorithm.HS256,
        secret=b"secret",
        expires_in=900,
    )

    claims = verify_jwt(
        token,
        algorithm=SymmetricAlgorithm.HS256,
        secret=b"secret",
        public_key=None,
    )

    assert claims is not None
    assert claims["sub"] == "test"


def test_verify_jwt_rejects_mismatched_issuer() -> None:
    """Tokens with the wrong issuer are rejected when an issuer is expected."""
    token = create_jwt(
        {"sub": "test", "iss": "https://issuer.example.com"},
        SymmetricAlgorithm.HS256,
        secret=b"secret",
    )

    assert (
        verify_jwt(
            token,
            algorithm=SymmetricAlgorithm.HS256,
            secret=b"secret",
            public_key=None,
            issuer="https://other.example.com",
        )
        is None
    )


def test_verify_jwt_accepts_matching_issuer() -> None:
    """Tokens with a matching issuer are accepted."""
    token = create_jwt(
        {"sub": "test", "iss": "https://issuer.example.com"},
        SymmetricAlgorithm.HS256,
        secret=b"secret",
        expires_in=900,
    )

    claims = verify_jwt(
        token,
        algorithm=SymmetricAlgorithm.HS256,
        secret=b"secret",
        public_key=None,
        issuer="https://issuer.example.com",
    )

    assert claims is not None
    assert claims["iss"] == "https://issuer.example.com"


def test_verify_jwt_rejects_missing_exp() -> None:
    """Tokens without an exp claim are rejected."""
    token = create_jwt({"sub": "test"}, SymmetricAlgorithm.HS256, secret=b"secret")

    assert (
        verify_jwt(
            token,
            algorithm=SymmetricAlgorithm.HS256,
            secret=b"secret",
            public_key=None,
        )
        is None
    )
