"""Tests for the client_credentials grant handler."""

import base64
import os
from collections.abc import Generator
from pathlib import Path

import pytest
from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.client_credentials_grant import handle_client_credentials
from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import ClientRepository, TokenRepository, database, init_db
from basic_oauth2_server.exceptions import (
    InvalidAudienceException,
    InvalidClientException,
    InvalidScopeException,
)


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = "test-app-key-1234567890_padded!!"


def b64(value: str) -> str:
    """Base64-encode a plain string the same way the OAuth server expects."""
    return base64.b64encode(value.encode()).decode()


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    """Return the database path for a test."""
    return str(tmp_path / "test.db")


@pytest.fixture(autouse=True)
def configured_database(db_path: str) -> Generator[None, None, None]:
    """Configure and seed the database for each test."""
    init_db(db_path)
    with database.connect() as db:
        ClientRepository(db).create(
            client_id="test-client",
            client_secret=b"test-secret",
            algorithm=SymmetricAlgorithm.HS256,
            signing_secret=b"signing-secret-1234567890abcdef",
            scopes=["read", "write"],
            audiences=["https://api.example.com"],
            redirect_uris=None,
            title=None,
        )
    yield
    database.reset()


@pytest.fixture
def config(db_path: str) -> ServerConfig:
    """Return server config for the configured test database."""
    return ServerConfig(db_path=db_path)


def test_success_form_credentials(config: ServerConfig) -> None:
    """Token is returned when form credentials are valid."""
    with database.connect() as db:
        data = handle_client_credentials(
            client_id="test-client",
            client_secret=b64("test-secret"),
            scope=None,
            audience=None,
            client_repo=ClientRepository(db),
            token_repo=TokenRepository(db, config),
        )
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] == 3600


def test_success_with_scope(config: ServerConfig) -> None:
    """Scope claim is included in the response when a single scope is requested."""
    with database.connect() as db:
        data = handle_client_credentials(
            client_id="test-client",
            client_secret=b64("test-secret"),
            scope="read",
            audience=None,
            client_repo=ClientRepository(db),
            token_repo=TokenRepository(db, config),
        )
    assert data["scope"] == "read"


def test_success_with_multiple_scopes(config: ServerConfig) -> None:
    """Multiple space-separated scopes are all returned in the response."""
    with database.connect() as db:
        data = handle_client_credentials(
            client_id="test-client",
            client_secret=b64("test-secret"),
            scope="read write",
            audience=None,
            client_repo=ClientRepository(db),
            token_repo=TokenRepository(db, config),
        )
    assert set(data["scope"].split()) == {"read", "write"}


def test_success_with_audience(config: ServerConfig) -> None:
    """Request succeeds when audience is in the allowed list."""
    with database.connect() as db:
        data = handle_client_credentials(
            client_id="test-client",
            client_secret=b64("test-secret"),
            scope=None,
            audience="https://api.example.com",
            client_repo=ClientRepository(db),
            token_repo=TokenRepository(db, config),
        )
    assert "access_token" in data


def test_missing_credentials_raises(config: ServerConfig) -> None:
    """Missing credentials are rejected."""
    with database.connect() as db:
        with pytest.raises(InvalidClientException):
            handle_client_credentials(
                client_id=None,
                client_secret=None,
                scope=None,
                audience=None,
                client_repo=ClientRepository(db),
                token_repo=TokenRepository(db, config),
            )


def test_invalid_base64_secret_raises(config: ServerConfig) -> None:
    """Invalid secrets are rejected."""
    with database.connect() as db:
        with pytest.raises(InvalidClientException):
            handle_client_credentials(
                client_id="test-client",
                client_secret="not-valid-base64!!!",
                scope=None,
                audience=None,
                client_repo=ClientRepository(db),
                token_repo=TokenRepository(db, config),
            )


def test_unknown_client_raises(config: ServerConfig) -> None:
    """Unknown clients are rejected."""
    with database.connect() as db:
        with pytest.raises(InvalidClientException):
            handle_client_credentials(
                client_id="no-such-client",
                client_secret=b64("whatever"),
                scope=None,
                audience=None,
                client_repo=ClientRepository(db),
                token_repo=TokenRepository(db, config),
            )


def test_wrong_secret_raises(config: ServerConfig) -> None:
    """Wrong client secrets are rejected."""
    with database.connect() as db:
        with pytest.raises(InvalidClientException):
            handle_client_credentials(
                client_id="test-client",
                client_secret=b64("wrong-secret"),
                scope=None,
                audience=None,
                client_repo=ClientRepository(db),
                token_repo=TokenRepository(db, config),
            )


def test_invalid_scope_raises(config: ServerConfig) -> None:
    """Invalid scopes are rejected."""
    with database.connect() as db:
        with pytest.raises(InvalidScopeException):
            handle_client_credentials(
                client_id="test-client",
                client_secret=b64("test-secret"),
                scope="admin",
                audience=None,
                client_repo=ClientRepository(db),
                token_repo=TokenRepository(db, config),
            )


def test_partially_invalid_scope_raises(config: ServerConfig) -> None:
    """A mix of valid and invalid scopes is still rejected."""
    with database.connect() as db:
        with pytest.raises(InvalidScopeException):
            handle_client_credentials(
                client_id="test-client",
                client_secret=b64("test-secret"),
                scope="read admin",
                audience=None,
                client_repo=ClientRepository(db),
                token_repo=TokenRepository(db, config),
            )


def test_invalid_audience_raises(config: ServerConfig) -> None:
    """Invalid audiences are rejected."""
    with database.connect() as db:
        with pytest.raises(InvalidAudienceException):
            handle_client_credentials(
                client_id="test-client",
                client_secret=b64("test-secret"),
                scope=None,
                audience="https://evil.example.com",
                client_repo=ClientRepository(db),
                token_repo=TokenRepository(db, config),
            )


def test_unexpected_exception_raises_server_error(
    config: ServerConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unexpected error during token creation raises OAuthServerErrorException."""
    from basic_oauth2_server.exceptions import OAuthServerErrorException

    def _boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("disk exploded")

    monkeypatch.setattr(TokenRepository, "issue_access_token", _boom)
    with database.connect() as db:
        with pytest.raises(
            OAuthServerErrorException, match="Failed to create access token"
        ):
            handle_client_credentials(
                client_id="test-client",
                client_secret=b64("test-secret"),
                scope=None,
                audience=None,
                client_repo=ClientRepository(db),
                token_repo=TokenRepository(db, config),
            )
