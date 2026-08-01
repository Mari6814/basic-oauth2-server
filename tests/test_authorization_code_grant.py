"""Tests for the authorization_code grant handler."""

import base64
import hashlib
import os
import secrets
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.authorization_code_grant import (
    handle_authorize as _handle_authorize,
    handle_authorization_code as _handle_authorization_code,
    handle_refresh_token as _handle_refresh_token,
)
from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import (
    AuthorizationCode,
    ClientRepository,
    RefreshToken,
    database,
    init_db,
    TokenRepository,
    UserRepository,
)
from basic_oauth2_server.exceptions import (
    AuthorizationRedirectException,
    InvalidClientException,
    InvalidGrantException,
    InvalidRequestException,
)


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = "test-authcode-key-1234567890!!!!"


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
            redirect_uris=["https://example.com/callback"],
            title=None,
        )
        UserRepository(db).create("testuser", "testpass")
    yield
    database.reset()


@pytest.fixture
def config(db_path: str) -> ServerConfig:
    """Return server config for the configured test database."""
    return ServerConfig(db_path=db_path)


def _repo_config(refresh_token_expires_in: int = 2592000) -> ServerConfig:
    """Build a server config for repository helpers."""
    return ServerConfig(
        db_path=database._db_path or "./oauth.db",
        refresh_token_expires_in=refresh_token_expires_in,
    )


def create_client(**kwargs: object) -> object:
    """Create a client through the client repository."""
    with database.connect() as db:
        return ClientRepository(db).create(**kwargs)


def create_user(username: str, password: str) -> object:
    """Create a user through the user repository."""
    with database.connect() as db:
        return UserRepository(db).create(username, password)


def create_authorization_code(
    *,
    client_id: str,
    user_id: str,
    redirect_uri: str | None,
    scope: str | None,
    audience: str | None,
    state: str | None,
    code_challenge: str | None,
    consent_jti: str,
    code_challenge_method: str = "S256",
    expires_in: int = 600,
) -> str:
    """Create an authorization code through the token repository."""
    with database.connect() as db:
        return TokenRepository(db, _repo_config()).create_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            audience=audience,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            consent_jti=consent_jti,
            expires_in=expires_in,
        )


def create_refresh_token(
    *,
    client_id: str,
    user_id: str,
    scope: str | None,
    audience: str | None,
    expires_in: int,
) -> str:
    """Create a refresh token through the token repository."""
    with database.connect() as db:
        client = ClientRepository(db).get(client_id)
        assert client is not None
        return TokenRepository(
            db, _repo_config(refresh_token_expires_in=expires_in)
        ).issue_refresh_token(
            client=client,
            user_id=user_id,
            scopes=scope.split() if scope else None,
            audience=audience,
        )


def get_session() -> object:
    """Return a raw SQLAlchemy session for direct inspection."""
    return database.connect()._session


def handle_authorize(
    *,
    authorized_username: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: list[str] | None,
    audience: str | None,
    state: str,
    config: ServerConfig,
) -> dict[str, object]:
    """Call handle_authorize with repositories wired in."""
    with database.connect() as db:
        return _handle_authorize(
            authorized_username=authorized_username,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            audience=audience,
            state=state,
            config=config,
            client_repo=ClientRepository(db),
        )


def handle_authorization_code(
    *,
    config: ServerConfig,
    client_id: str,
    client_secret: str,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> dict[str, object]:
    """Call handle_authorization_code with repositories wired in."""
    with database.connect() as db:
        return _handle_authorization_code(
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            client_repo=ClientRepository(db),
            token_repo=TokenRepository(db, config),
        )


def handle_refresh_token(
    *,
    config: ServerConfig,
    client_id: str,
    client_secret: str,
    refresh_token: str | None,
) -> dict[str, object]:
    """Call handle_refresh_token with repositories wired in."""
    with database.connect() as db:
        return _handle_refresh_token(
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
            client_repo=ClientRepository(db),
            token_repo=TokenRepository(db, config),
        )


def b64(s: str) -> str:
    """Encode a string as base64 text."""
    return base64.b64encode(s.encode()).decode()


def _s256_challenge(verifier: str) -> str:
    """Build an S256 PKCE challenge from a verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class TestHandleAuthorize:
    """Tests for the consent step of the authorization code flow."""

    def test_invalid_code_challenge_method_raises(self, config: ServerConfig) -> None:
        """Unsupported PKCE methods are rejected."""
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
        """Unknown clients are rejected."""
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

    def test_invalid_scope_raises_redirect_exception(
        self, config: ServerConfig
    ) -> None:
        """Invalid scopes are returned as redirect errors."""
        with pytest.raises(AuthorizationRedirectException) as exc_info:
            handle_authorize(
                authorized_username="testuser",
                client_id="test-client",
                redirect_uri="https://example.com/callback",
                code_challenge="abc123",
                code_challenge_method="S256",
                scope=["admin"],
                audience=None,
                state="state123",
                config=config,
            )

        exc = exc_info.value
        assert exc.redirect_uri == "https://example.com/callback"
        assert exc.error == "invalid_scope"
        assert exc.description == "Invalid scopes: admin"
        assert exc.state == "state123"

    def test_invalid_audience_raises_redirect_exception(
        self, config: ServerConfig
    ) -> None:
        """Invalid audiences are returned as redirect errors."""
        with pytest.raises(AuthorizationRedirectException) as exc_info:
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

        exc = exc_info.value
        assert exc.redirect_uri == "https://example.com/callback"
        assert exc.error == "invalid_request"
        assert exc.description == "Invalid audience: https://evil.example.com"
        assert exc.state == "state123"


class TestHandleAuthorizationCode:
    """Tests for exchanging authorization codes for tokens."""

    def test_missing_code_raises(self, config: ServerConfig) -> None:
        """A missing authorization code is rejected."""
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
        """Unknown clients cannot exchange authorization codes."""
        code = create_authorization_code(
            client_id="test-client",
            user_id="testuser",
            redirect_uri=None,
            scope=None,
            audience=None,
            state=None,
            code_challenge="challenge",
            consent_jti=secrets.token_urlsafe(32),
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
            client_id="other-client",
            client_secret=b"other-secret",
            algorithm=SymmetricAlgorithm.HS256,
            signing_secret=b"other-signing-secret-1234567890",
        )
        code = create_authorization_code(
            client_id="test-client",
            user_id="testuser",
            redirect_uri=None,
            scope=None,
            audience=None,
            state=None,
            code_challenge="challenge",
            consent_jti=secrets.token_urlsafe(32),
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
        """Authorization codes are bound to their redirect URI."""
        code_verifier = "my-verifier-long-enough-for-s256"
        code = create_authorization_code(
            client_id="test-client",
            user_id="testuser",
            redirect_uri="https://example.com/callback",
            scope=None,
            audience=None,
            state=None,
            code_challenge=_s256_challenge(code_verifier),
            consent_jti=secrets.token_urlsafe(32),
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

    def test_successful_exchange_prunes_stale_authorization_codes(
        self, config: ServerConfig, db_path: str
    ) -> None:
        """Successful exchanges return a refresh token and prune stale auth codes."""
        code_verifier = "my-verifier-long-enough-for-s256"
        valid_code = create_authorization_code(
            client_id="test-client",
            user_id="testuser",
            redirect_uri="https://example.com/callback",
            scope="read write",
            audience=None,
            state=None,
            code_challenge=_s256_challenge(code_verifier),
            consent_jti=secrets.token_urlsafe(32),
        )

        expired_code = "expired-code"
        used_code = "used-code"
        with get_session() as session:
            session.add_all(
                [
                    AuthorizationCode(
                        code=expired_code,
                        client_id="test-client",
                        user_id="testuser",
                        redirect_uri="https://example.com/callback",
                        scope="read",
                        audience=None,
                        state=None,
                        code_challenge=_s256_challenge("expired-verifier"),
                        code_challenge_method="S256",
                        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
                        used=False,
                        consent_jti=secrets.token_urlsafe(32),
                    ),
                    AuthorizationCode(
                        code=used_code,
                        client_id="test-client",
                        user_id="testuser",
                        redirect_uri="https://example.com/callback",
                        scope="read",
                        audience=None,
                        state=None,
                        code_challenge=_s256_challenge("used-verifier"),
                        code_challenge_method="S256",
                        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                        used=True,
                        consent_jti=secrets.token_urlsafe(32),
                    ),
                ]
            )
            session.commit()

        response = handle_authorization_code(
            config=config,
            client_id="test-client",
            client_secret=b64("test-secret"),
            code=valid_code,
            redirect_uri="https://example.com/callback",
            code_verifier=code_verifier,
        )

        assert response["token_type"] == "Bearer"
        assert isinstance(response["refresh_token"], str)
        with get_session() as session:
            assert session.get(AuthorizationCode, expired_code) is None
            assert session.get(AuthorizationCode, used_code) is None


class TestHandleRefreshToken:
    """Tests for exchanging refresh tokens for rotated tokens."""

    def test_missing_refresh_token_raises(self, config: ServerConfig) -> None:
        """A missing refresh_token parameter is rejected."""
        with pytest.raises(InvalidRequestException, match="Missing refresh_token"):
            handle_refresh_token(
                config=config,
                client_id="test-client",
                client_secret=b64("test-secret"),
                refresh_token=None,
            )

    def test_valid_refresh_token_returns_rotated_tokens(
        self, config: ServerConfig, db_path: str
    ) -> None:
        """A valid refresh token issues a new access token and replacement refresh token."""
        refresh_token = create_refresh_token(
            client_id="test-client",
            user_id="testuser",
            scope="read write",
            audience="https://api.example.com",
            expires_in=3600,
        )

        response = handle_refresh_token(
            config=config,
            client_id="test-client",
            client_secret=b64("test-secret"),
            refresh_token=refresh_token,
        )

        assert response["token_type"] == "Bearer"
        assert isinstance(response["access_token"], str)
        assert isinstance(response["refresh_token"], str)
        assert response["refresh_token"] != refresh_token
        assert response["scope"] == "read write"

    def test_consumed_refresh_token_cannot_be_reused(
        self, config: ServerConfig, db_path: str
    ) -> None:
        """Refresh tokens are single-use and invalid after rotation."""
        refresh_token = create_refresh_token(
            client_id="test-client",
            user_id="testuser",
            scope="read",
            audience=None,
            expires_in=3600,
        )

        handle_refresh_token(
            config=config,
            client_id="test-client",
            client_secret=b64("test-secret"),
            refresh_token=refresh_token,
        )

        with pytest.raises(
            InvalidGrantException, match="Invalid or expired refresh token"
        ):
            handle_refresh_token(
                config=config,
                client_id="test-client",
                client_secret=b64("test-secret"),
                refresh_token=refresh_token,
            )

    def test_expired_refresh_token_raises(
        self, config: ServerConfig, db_path: str
    ) -> None:
        """Expired refresh tokens are rejected."""
        refresh_token = create_refresh_token(
            client_id="test-client",
            user_id="testuser",
            scope="read",
            audience=None,
            expires_in=-1,
        )

        with pytest.raises(
            InvalidGrantException, match="Invalid or expired refresh token"
        ):
            handle_refresh_token(
                config=config,
                client_id="test-client",
                client_secret=b64("test-secret"),
                refresh_token=refresh_token,
            )

    def test_wrong_client_refresh_token_raises(
        self, config: ServerConfig, db_path: str
    ) -> None:
        """Refresh tokens cannot be exchanged by a different client."""
        create_client(
            client_id="other-client",
            client_secret=b"other-secret",
            algorithm=SymmetricAlgorithm.HS256,
            signing_secret=b"other-signing-secret-1234567890",
        )
        refresh_token = create_refresh_token(
            client_id="test-client",
            user_id="testuser",
            scope="read",
            audience=None,
            expires_in=3600,
        )

        with pytest.raises(
            InvalidGrantException, match="Invalid or expired refresh token"
        ):
            handle_refresh_token(
                config=config,
                client_id="other-client",
                client_secret=b64("other-secret"),
                refresh_token=refresh_token,
            )

        with get_session() as session:
            assert session.get(RefreshToken, refresh_token) is None


class TestVerifyPkceUnsupportedMethods:
    """Tests for PKCE method validation."""

    @pytest.mark.parametrize("method", ["plain", "S512", "INVALID"])
    def test_unsupported_method_rejected(
        self, config: ServerConfig, method: str
    ) -> None:
        """Only S256 is accepted; plain, S512, and anything else must be rejected."""
        with pytest.raises(InvalidRequestException, match="code_challenge_method"):
            handle_authorize(
                authorized_username="testuser",
                client_id="test-client",
                redirect_uri="http://localhost/callback",
                code_challenge="dummychallenge",
                code_challenge_method=method,
                scope=None,
                audience=None,
                state="state",
                config=config,
            )
