"""Tests for token_service.create_access_token_for_client."""

import base64
import json
import os
from pathlib import Path

import pytest
from jws_algorithms import SymmetricAlgorithm, AsymmetricAlgorithm

from basic_oauth2_server.db import create_client, get_client
from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.exceptions import OAuthServerErrorException
from basic_oauth2_server.token_service import (
    create_access_token_for_client,
    create_client_refresh_token,
)

KEYS_DIR = Path(__file__).parent / "keys"


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = base64.b64encode(b"test-app-key-1234567890").decode()


def test_access_token_symmetric(tmp_path: Path) -> None:
    """Test access token creation for symmetric algorithm (HS256)."""
    db_path = str(tmp_path / "test.db")
    secret_file = tmp_path / "hs256.secret"
    secret_file.write_bytes(os.urandom(32))

    create_client(
        db_path=db_path,
        client_id="client1",
        client_secret=b"secret",
        algorithm=SymmetricAlgorithm.HS256,
        signing_secret=secret_file.read_bytes(),
        scopes=["read"],
    )
    client = get_client(db_path, "client1")
    assert client
    config = ServerConfig()

    token = create_access_token_for_client(
        config, client, scopes=["read"], audience="aud"
    )

    parts = token.split(".")
    assert len(parts) == 3
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert header["alg"] == "HS256"
    assert payload["sub"] == "client1"
    assert payload["aud"] == "aud"
    assert set(payload["scope"].split()) == {"read"}


def test_access_token_asymmetric(tmp_path: Path) -> None:
    """Test access token creation for asymmetric algorithm (RS256)."""
    db_path = str(tmp_path / "test.db")
    create_client(
        db_path=db_path,
        client_id="client2",
        client_secret=b"secret",
        algorithm=AsymmetricAlgorithm.RS256,
    )
    client = get_client(db_path, "client2")
    assert client
    config = ServerConfig(
        rsa_private_key=f"@{KEYS_DIR / 'rsa-private.pem'}",
        rsa_key_id="kid123",
    )

    token = create_access_token_for_client(
        config, client, scopes=["write"], audience="aud2"
    )

    parts = token.split(".")
    assert len(parts) == 3
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert header["alg"] == "RS256"
    assert header["kid"] == "kid123"
    assert payload["sub"] == "client2"
    assert payload["aud"] == "aud2"
    assert set(payload["scope"].split()) == {"write"}


def test_access_token_missing_secret(tmp_path: Path) -> None:
    """Test error when symmetric client has no signing secret configured."""
    db_path = str(tmp_path / "test.db")
    create_client(
        db_path=db_path,
        client_id="client3",
        client_secret=b"secret",
        algorithm=SymmetricAlgorithm.HS256,
        # no signing_secret
    )
    client = get_client(db_path, "client3")
    assert client
    config = ServerConfig()
    with pytest.raises(ValueError, match="has no signing secret configured"):
        create_access_token_for_client(config, client)


def test_access_token_missing_key(tmp_path: Path) -> None:
    """Test error when asymmetric config has no private key configured."""
    db_path = str(tmp_path / "test.db")
    create_client(
        db_path=db_path,
        client_id="client4",
        client_secret=b"secret",
        algorithm=AsymmetricAlgorithm.RS256,
    )
    client = get_client(db_path, "client4")
    assert client
    config = ServerConfig()  # no rsa_private_key
    with pytest.raises(ValueError, match="No private key configured"):
        create_access_token_for_client(config, client)


def test_create_client_refresh_token_returns_none() -> None:
    """create_client_refresh_token is a stub that returns None."""
    result = create_client_refresh_token(ServerConfig())
    assert result is None


def test_oauth_server_error_exception_stores_description() -> None:
    """OAuthServerErrorException captures the description and error code."""
    exc = OAuthServerErrorException("Something went wrong")
    assert exc.error == "server_error"
    assert exc.description == "Something went wrong"
    assert exc.status_code == 500
