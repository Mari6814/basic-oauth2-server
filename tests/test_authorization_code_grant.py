"""Tests for the authorization_code grant handler."""

import base64
import hashlib
import os
from pathlib import Path

import pytest
from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.authorization_code_grant import (
    handle_authorize,
    handle_authorization_code,
)
from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import (
    create_authorization_code,
    create_client,
    create_user,
)
from basic_oauth2_server.exceptions import (
    InvalidAudienceException,
    InvalidClientException,
    InvalidGrantException,
    InvalidRequestException,
)


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = base64.b64encode(b"test-authcode-key-1234567890!!!!").decode()


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
        redirect_uris=["https://example.com/callback"],
    )
    create_user(path, "testuser", "testpass")
    return path


@pytest.fixture
def config(db_path: str) -> ServerConfig:
    return ServerConfig(db_path=db_path)


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class TestHandleAuthorize:
    def test_invalid_code_challenge_method_raises(self, config: ServerConfig) -> None:
        with pytest.raises(InvalidRequestException, match="code_challenge_method"):
            handle_authorize(
                authorized_username="testuser",
                client_id="test-client",
                redirect_uri="https://example.com/callback",
                code_challenge="abc123",
                code_challenge_method="INVALID",
                scope=None,
                audience=None,
                state="state123",
                config=config,
            )

    def test_invalid_client_raises(self, config: ServerConfig) -> None:
        with pytest.raises(InvalidClientException, match="Invalid client"):
            handle_authorize(
                authorized_username="testuser",
                client_id="nonexistent-client",
                redirect_uri="https://example.com/callback",
                code_challenge="abc123",
                code_challenge_method="S256",
                scope=None,
                audience=None,
                state="state123",
                config=config,
            )

    def test_invalid_audience_raises(self, config: ServerConfig) -> None:
        with pytest.raises(InvalidAudienceException, match="Invalid audience"):
            handle_authorize(
                authorized_username="testuser",
                client_id="test-client",
                redirect_uri="https://example.com/callback",
                code_challenge="abc123",
                code_challenge_method="S256",
                scope=None,
                audience="https://evil.example.com",
                state="state123",
                config=config,
            )


class TestHandleAuthorizationCode:
    def test_missing_code_raises(self, config: ServerConfig) -> None:
        with pytest.raises(InvalidRequestException, match="Missing authorization code"):
            handle_authorization_code(
                config=config,
                client_id="test-client",
                client_secret=b64("test-secret"),
                code=None,
                redirect_uri=None,
                code_verifier="verifier",
            )

    def test_client_not_found_raises(self, config: ServerConfig, db_path: str) -> None:
        code = create_authorization_code(
            db_path=db_path,
            client_id="test-client",
            user_id="testuser",
            redirect_uri=None,
            scope=None,
            audience=None,
            state=None,
            code_challenge="challenge",
        )
        with pytest.raises(InvalidClientException, match="Client not found"):
            handle_authorization_code(
                config=config,
                client_id="nonexistent-client",
                client_secret=b64("test-secret"),
                code=code,
                redirect_uri=None,
                code_verifier="verifier",
            )

    def test_client_id_mismatch_raises(
        self, config: ServerConfig, db_path: str
    ) -> None:
        """Authorization code was issued for a different client."""
        create_client(
            db_path=db_path,
            client_id="other-client",
            client_secret=b"other-secret",
            algorithm=SymmetricAlgorithm.HS256,
            signing_secret=b"other-signing-secret-1234567890",
        )
        code = create_authorization_code(
            db_path=db_path,
            client_id="test-client",
            user_id="testuser",
            redirect_uri=None,
            scope=None,
            audience=None,
            state=None,
            code_challenge="challenge",
        )
        with pytest.raises(InvalidGrantException, match="Client ID mismatch"):
            handle_authorization_code(
                config=config,
                client_id="other-client",
                client_secret=b64("other-secret"),
                code=code,
                redirect_uri=None,
                code_verifier="verifier",
            )

    def test_redirect_uri_mismatch_raises(
        self, config: ServerConfig, db_path: str
    ) -> None:
        code_verifier = "my-verifier-long-enough-for-s256"
        code = create_authorization_code(
            db_path=db_path,
            client_id="test-client",
            user_id="testuser",
            redirect_uri="https://example.com/callback",
            scope=None,
            audience=None,
            state=None,
            code_challenge=_s256_challenge(code_verifier),
        )
        with pytest.raises(InvalidGrantException, match="Redirect URI mismatch"):
            handle_authorization_code(
                config=config,
                client_id="test-client",
                client_secret=b64("test-secret"),
                code=code,
                redirect_uri="https://evil.example.com/callback",
                code_verifier=code_verifier,
            )


class TestVerifyPkcePlain:
    def test_plain_method_succeeds(self, config: ServerConfig, db_path: str) -> None:
        """PKCE with 'plain' method succeeds when verifier equals the challenge."""
        code_verifier = "my-plain-verifier-string"
        code = create_authorization_code(
            db_path=db_path,
            client_id="test-client",
            user_id="testuser",
            redirect_uri=None,
            scope=None,
            audience=None,
            state=None,
            code_challenge=code_verifier,
            code_challenge_method="plain",
        )
        result = handle_authorization_code(
            config=config,
            client_id="test-client",
            client_secret=b64("test-secret"),
            code=code,
            redirect_uri=None,
            code_verifier=code_verifier,
        )
        assert "access_token" in result
        assert result["token_type"] == "Bearer"
