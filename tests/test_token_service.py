"""Tests for repository-based token issuance helpers."""

import base64
import json
import os
from collections.abc import Generator
from pathlib import Path

import pytest
from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import (
    ClientRepository,
    RefreshToken,
    TokenRepository,
    UserRepository,
    database,
    init_db,
)
from basic_oauth2_server.exceptions import OAuthServerErrorException

KEYS_DIR = Path(__file__).parent / "keys"


@pytest.fixture(autouse=True)
def app_key() -> None:
    """Set the application key for token service tests."""
    os.environ["APP_KEY"] = "test-app-key-1234567890_padded!!"


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    """Return the database path for a token service test."""
    return str(tmp_path / "test.db")


@pytest.fixture(autouse=True)
def configured_database(db_path: str) -> Generator[None, None, None]:
    """Configure and reset the module-level database around each test."""
    init_db(db_path)
    yield
    database.reset()


def test_access_token_symmetric(tmp_path: Path, db_path: str) -> None:
    """Test access token creation for symmetric algorithm."""
    secret_file = tmp_path / "hs256.secret"
    secret_file.write_bytes(os.urandom(32))

    with database.connect() as db:
        client = ClientRepository(db).create(
            client_id="client1",
            client_secret=b"secret",
            algorithm=SymmetricAlgorithm.HS256,
            signing_secret=secret_file.read_bytes(),
            scopes=["read"],
            audiences=None,
            redirect_uris=None,
            title=None,
        )
        token = TokenRepository(db, ServerConfig(db_path=db_path)).issue_access_token(
            client=client,
            subject="client1",
            scopes=["read"],
            audience="aud",
        )

    parts = token.split(".")
    assert len(parts) == 3
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert header["alg"] == "HS256"
    assert payload["sub"] == "client1"
    assert payload["aud"] == "aud"
    assert set(payload["scope"].split()) == {"read"}


def test_access_token_asymmetric(db_path: str) -> None:
    """Test access token creation for asymmetric algorithm."""
    with database.connect() as db:
        client = ClientRepository(db).create(
            client_id="client2",
            client_secret=b"secret",
            algorithm=AsymmetricAlgorithm.RS256,
            signing_secret=None,
            scopes=None,
            audiences=None,
            redirect_uris=None,
            title=None,
        )
        token = TokenRepository(
            db,
            ServerConfig(
                db_path=db_path,
                rsa_private_key=f"@{KEYS_DIR / 'rsa-private.pem'}",
                rsa_key_id="kid123",
            ),
        ).issue_access_token(
            client=client,
            subject="client2",
            scopes=["write"],
            audience="aud2",
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


def test_access_token_missing_secret(db_path: str) -> None:
    """Test error when symmetric client has no signing secret configured."""
    with database.connect() as db:
        client = ClientRepository(db).create(
            client_id="client3",
            client_secret=b"secret",
            algorithm=SymmetricAlgorithm.HS256,
            signing_secret=None,
            scopes=None,
            audiences=None,
            redirect_uris=None,
            title=None,
        )
        with pytest.raises(ValueError, match="has no signing secret configured"):
            TokenRepository(db, ServerConfig(db_path=db_path)).issue_access_token(
                client=client,
                subject="client3",
                scopes=None,
                audience=None,
            )


def test_access_token_missing_key(db_path: str) -> None:
    """Test error when asymmetric config has no private key configured."""
    with database.connect() as db:
        client = ClientRepository(db).create(
            client_id="client4",
            client_secret=b"secret",
            algorithm=AsymmetricAlgorithm.RS256,
            signing_secret=None,
            scopes=None,
            audiences=None,
            redirect_uris=None,
            title=None,
        )
        with pytest.raises(ValueError, match="No private key configured"):
            TokenRepository(db, ServerConfig(db_path=db_path)).issue_access_token(
                client=client,
                subject="client4",
                scopes=None,
                audience=None,
            )


def test_create_refresh_token_for_client_persists_token(db_path: str) -> None:
    """Refresh token helper stores an opaque token in the database."""
    with database.connect() as db:
        client_repo = ClientRepository(db)
        user_repo = UserRepository(db)
        client = client_repo.create(
            client_id="client-refresh",
            client_secret=b"secret",
            algorithm=SymmetricAlgorithm.HS256,
            signing_secret=b"refresh-signing-secret-1234567890",
            scopes=None,
            audiences=None,
            redirect_uris=None,
            title=None,
        )
        user_repo.create("alice", "password")
        token = TokenRepository(
            db, ServerConfig(db_path=db_path, refresh_token_expires_in=1234)
        ).issue_refresh_token(
            client=client,
            user_id="alice",
            scopes=["read", "write"],
            audience="https://api.example.com",
        )
        persisted = db._session.get(RefreshToken, token)

    assert isinstance(token, str)
    assert "." not in token
    assert persisted is not None
    assert persisted.client_id == "client-refresh"
    assert persisted.user_id == "alice"
    assert persisted.scope == "read write"
    assert persisted.audience == "https://api.example.com"


def test_oauth_server_error_exception_stores_description() -> None:
    """OAuthServerErrorException captures the description and error code."""
    exc = OAuthServerErrorException("Something went wrong")
    assert exc.error == "server_error"
    assert exc.description == "Something went wrong"
    assert exc.status_code == 500
