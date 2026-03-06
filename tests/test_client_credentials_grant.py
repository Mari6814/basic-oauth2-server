"""Tests for the client_credentials grant handler."""

import base64
import json
import os
from pathlib import Path

import pytest
from fastapi.security import HTTPBasicCredentials
from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.client_credentials_grant import handle_client_credentials
from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import create_client
from basic_oauth2_server.exceptions import (
    InvalidAudienceException,
    InvalidClientException,
    InvalidScopeException,
)


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = base64.b64encode(b"test-app-key-1234567890").decode()


def b64(s: str) -> str:
    """Base64-encode a plain string the same way the OAuth server expects."""
    return base64.b64encode(s.encode()).decode()


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    create_client(
        db_path=path,
        client_id="test-client",
        client_secret=b"test-secret",
        algorithm=SymmetricAlgorithm.HS256,
        signing_secret=b"signing-secret-1234567890abcdef",
        scopes=["read", "write"],
        audiences=["https://api.example.com"],
    )
    return path


@pytest.fixture
def config(db_path: str) -> ServerConfig:
    return ServerConfig(db_path=db_path)


def test_success_form_credentials(config: ServerConfig) -> None:
    """Token is returned when form credentials are valid."""
    response = handle_client_credentials(
        config=config,
        client_id="test-client",
        client_secret=b64("test-secret"),
        scope=None,
        audience=None,
        basic_credentials=None,
    )
    data = json.loads(response.body)
    assert response.status_code == 200
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] == 3600


def test_success_basic_auth(config: ServerConfig) -> None:
    """Token is returned when Basic auth credentials are valid."""
    creds = HTTPBasicCredentials(username="test-client", password=b64("test-secret"))
    response = handle_client_credentials(
        config=config,
        client_id=None,
        client_secret=None,
        scope=None,
        audience=None,
        basic_credentials=creds,
    )
    data = json.loads(response.body)
    assert response.status_code == 200
    assert "access_token" in data


def test_success_with_scope(config: ServerConfig) -> None:
    """Scope claim is included in the response when a single scope is requested."""
    response = handle_client_credentials(
        config=config,
        client_id="test-client",
        client_secret=b64("test-secret"),
        scope="read",
        audience=None,
        basic_credentials=None,
    )
    data = json.loads(response.body)
    assert response.status_code == 200
    assert data["scope"] == "read"


def test_success_with_multiple_scopes(config: ServerConfig) -> None:
    """Multiple space-separated scopes are all returned in the response."""
    response = handle_client_credentials(
        config=config,
        client_id="test-client",
        client_secret=b64("test-secret"),
        scope="read write",
        audience=None,
        basic_credentials=None,
    )
    data = json.loads(response.body)
    assert response.status_code == 200
    assert set(data["scope"].split()) == {"read", "write"}


def test_success_with_audience(config: ServerConfig) -> None:
    """Request succeeds when audience is in the allowed list."""
    response = handle_client_credentials(
        config=config,
        client_id="test-client",
        client_secret=b64("test-secret"),
        scope=None,
        audience="https://api.example.com",
        basic_credentials=None,
    )
    assert response.status_code == 200


def test_basic_auth_takes_priority(config: ServerConfig) -> None:
    """Basic auth credentials are used even when form credentials are also present."""
    creds = HTTPBasicCredentials(username="test-client", password=b64("test-secret"))
    response = handle_client_credentials(
        config=config,
        client_id="test-client",
        client_secret=b64("wrong-secret"),
        scope=None,
        audience=None,
        basic_credentials=creds,
    )
    assert response.status_code == 200


def test_missing_credentials_raises(config: ServerConfig) -> None:
    with pytest.raises(InvalidClientException):
        handle_client_credentials(
            config=config,
            client_id=None,
            client_secret=None,
            scope=None,
            audience=None,
            basic_credentials=None,
        )


def test_invalid_base64_secret_raises(config: ServerConfig) -> None:
    with pytest.raises(InvalidClientException):
        handle_client_credentials(
            config=config,
            client_id="test-client",
            client_secret="not-valid-base64!!!",
            scope=None,
            audience=None,
            basic_credentials=None,
        )


def test_unknown_client_raises(config: ServerConfig) -> None:
    with pytest.raises(InvalidClientException):
        handle_client_credentials(
            config=config,
            client_id="no-such-client",
            client_secret=b64("whatever"),
            scope=None,
            audience=None,
            basic_credentials=None,
        )


def test_wrong_secret_raises(config: ServerConfig) -> None:
    with pytest.raises(InvalidClientException):
        handle_client_credentials(
            config=config,
            client_id="test-client",
            client_secret=b64("wrong-secret"),
            scope=None,
            audience=None,
            basic_credentials=None,
        )


def test_invalid_scope_raises(config: ServerConfig) -> None:
    with pytest.raises(InvalidScopeException):
        handle_client_credentials(
            config=config,
            client_id="test-client",
            client_secret=b64("test-secret"),
            scope="admin",
            audience=None,
            basic_credentials=None,
        )


def test_partially_invalid_scope_raises(config: ServerConfig) -> None:
    """A mix of valid and invalid scopes is still rejected."""
    with pytest.raises(InvalidScopeException):
        handle_client_credentials(
            config=config,
            client_id="test-client",
            client_secret=b64("test-secret"),
            scope="read admin",
            audience=None,
            basic_credentials=None,
        )


def test_invalid_audience_raises(config: ServerConfig) -> None:
    with pytest.raises(InvalidAudienceException):
        handle_client_credentials(
            config=config,
            client_id="test-client",
            client_secret=b64("test-secret"),
            scope=None,
            audience="https://evil.example.com",
            basic_credentials=None,
        )
