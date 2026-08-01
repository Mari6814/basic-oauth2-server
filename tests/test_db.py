"""Tests for database models and auto-managed timestamp columns."""

import base64
import hashlib
import os
import secrets
import time
from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.db import (
    AuthorizationCode,
    Client,
    ClientRepository,
    DbSession,
    database,
    TokenRepository,
    UserRepository,
)
from basic_oauth2_server.exceptions import InvalidGrantException
from basic_oauth2_server.config import ServerConfig


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = "test-app-key-1234567890_padded!!"


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    """Return the database path for a test."""
    return str(tmp_path / "test.db")


@pytest.fixture(autouse=True)
def configured_database(db_path: str) -> Generator[None, None, None]:
    """Configure and reset the module-level database around each test."""
    database.configure(db_path)
    yield
    database.reset()


@pytest.fixture
def db_session() -> Generator[DbSession, None, None]:
    """Yield a raw DbSession for tests that inspect ORM state directly."""
    assert database._session_factory is not None
    db = DbSession(database._session_factory())
    try:
        yield db
    finally:
        db.__exit__(None, None, None)


def _repo_config() -> ServerConfig:
    """Build a repository config for the active database."""
    return ServerConfig(db_path=database._db_path or "./oauth.db")


def create_client(**kwargs: object) -> Client:
    """Create a client through the repository."""
    with database.connect() as db:
        return ClientRepository(db).create(**kwargs)


def get_client(client_id: str) -> Client | None:
    """Load a client through the repository."""
    with database.connect() as db:
        return ClientRepository(db).get(client_id)


def create_user(username: str, password: str) -> object:
    """Create a user through the repository."""
    with database.connect() as db:
        return UserRepository(db).create(username, password)


def get_user(username: str) -> object | None:
    """Load a user through the repository."""
    with database.connect() as db:
        return UserRepository(db).get(username)


def delete_user(username: str) -> bool:
    """Delete a user through the repository."""
    with database.connect() as db:
        return UserRepository(db).delete(username)


def list_users() -> list[object]:
    """List users through the repository."""
    with database.connect() as db:
        return UserRepository(db).list()


def update_user_password(username: str, password: str) -> bool:
    """Update a user password through the repository."""
    with database.connect() as db:
        return UserRepository(db).update_password(username, password)


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
    """Create an authorization code through the repository."""
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


def get_authorization_code(code: str) -> AuthorizationCode | None:
    """Load an authorization code through the repository."""
    with database.connect() as db:
        return TokenRepository(db, _repo_config()).get_authorization_code(code)


def get_session() -> object:
    """Return a raw SQLAlchemy session for direct ORM manipulation."""
    return database.connect()._session


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware in UTC for consistent comparisons."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


class TestClientTimestamps:
    def test_created_at_set_on_insert(self, db_path: str) -> None:
        """created_at is populated automatically when a client is first created."""
        before = datetime.now(timezone.utc)
        create_client(
            client_id="c1",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )
        after = datetime.now(timezone.utc)

        client = get_client("c1")
        assert client is not None
        assert before <= _ensure_utc(client.created_at) <= after

    def test_updated_at_set_on_insert(self, db_path: str) -> None:
        """updated_at is populated automatically on initial insert."""
        before = datetime.now(timezone.utc)
        create_client(
            client_id="c2",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )
        after = datetime.now(timezone.utc)

        client = get_client("c2")
        assert client is not None
        assert before <= _ensure_utc(client.updated_at) <= after

    def test_updated_at_changes_on_update(self, db_path: str) -> None:
        """updated_at advances when the record is modified."""
        create_client(
            client_id="c3",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )

        client = get_client("c3")
        assert client is not None
        original_updated_at = client.updated_at

        time.sleep(0.01)

        with get_session() as session:
            c = session.get(Client, "c3")
            assert c is not None
            c.scopes = "read,write"
            session.commit()

        updated = get_client("c3")
        assert updated is not None
        assert updated.updated_at >= original_updated_at

    def test_created_at_unchanged_on_update(self, db_path: str) -> None:
        """created_at must not change when the record is updated."""
        create_client(
            client_id="c4",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )

        client = get_client("c4")
        assert client is not None
        original_created_at = client.created_at

        time.sleep(0.01)

        with get_session() as session:
            c = session.get(Client, "c4")
            assert c is not None
            c.scopes = "admin"
            session.commit()

        updated = get_client("c4")
        assert updated is not None
        assert updated.created_at == original_created_at


class TestAuthorizationCodeTimestamps:
    def test_created_at_set_on_insert(self, db_path: str) -> None:
        """created_at is populated automatically when an authorization code is created."""
        create_user("user1", "pw")
        before = datetime.now(timezone.utc)
        code = create_authorization_code(
            client_id="client1",
            user_id="user1",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
            consent_jti=secrets.token_urlsafe(32),
        )
        after = datetime.now(timezone.utc)

        record = get_authorization_code(code)
        assert record is not None
        assert before <= _ensure_utc(record.created_at) <= after

    def test_updated_at_set_on_insert(self, db_path: str) -> None:
        """updated_at is populated automatically on initial insert."""
        create_user("user1", "pw")
        before = datetime.now(timezone.utc)
        code = create_authorization_code(
            client_id="client1",
            user_id="user1",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
            consent_jti=secrets.token_urlsafe(32),
        )
        after = datetime.now(timezone.utc)

        record = get_authorization_code(code)
        assert record is not None
        assert before <= _ensure_utc(record.updated_at) <= after

    def test_updated_at_changes_on_update(self, db_path: str) -> None:
        """updated_at advances when an authorization code record is modified."""
        create_user("user1", "pw")
        code = create_authorization_code(
            client_id="client1",
            user_id="user1",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
            consent_jti=secrets.token_urlsafe(32),
        )
        record = get_authorization_code(code)
        assert record is not None
        original_updated_at = record.updated_at

        time.sleep(0.01)

        with get_session() as session:
            auth_code = session.get(AuthorizationCode, code)
            assert auth_code is not None
            auth_code.used = True
            session.commit()

        with get_session() as session:
            updated = session.get(AuthorizationCode, code)
            assert updated is not None
            assert updated.updated_at >= original_updated_at

    def test_reused_consent_jti_raises_invalid_grant(self, db_path: str) -> None:
        """create_authorization_code rejects a replayed consent token."""
        consent_jti = secrets.token_urlsafe(32)

        create_user("user1", "pw")
        create_authorization_code(
            client_id="client1",
            user_id="user1",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
            consent_jti=consent_jti,
        )

        with pytest.raises(InvalidGrantException, match="Consent token already used"):
            create_authorization_code(
                client_id="client1",
                user_id="user1",
                redirect_uri=None,
                scope="read",
                audience=None,
                state=None,
                code_challenge=None,
                consent_jti=consent_jti,
            )


class TestUser:
    def test_create_user_stores_hashed_password(self, db_path: str) -> None:
        """create_user persists the user and stores a bcrypt hash, not the plaintext."""
        user = create_user("alice", "s3cr3t")
        assert user.username == "alice"
        assert user.password_hash != "s3cr3t"
        assert user.password_hash.startswith("$2b$")

    def test_get_user_returns_user(self, db_path: str) -> None:
        """get_user returns the created user by username."""
        create_user("bob", "pass123")
        user = get_user("bob")
        assert user is not None
        assert user.username == "bob"

    def test_get_user_returns_none_for_missing(self, db_path: str) -> None:
        """get_user returns None when the username does not exist."""
        assert get_user("nobody") is None

    def test_verify_password_correct(self, db_path: str) -> None:
        """verify_password returns True for the correct password."""
        create_user("carol", "correct-horse")
        user = get_user("carol")
        assert user is not None
        assert user.verify_password("correct-horse") is True

    def test_verify_password_wrong(self, db_path: str) -> None:
        """verify_password returns False for an incorrect password."""
        create_user("dave", "correct-horse")
        user = get_user("dave")
        assert user is not None
        assert user.verify_password("wrong-password") is False

    def test_verify_password_uses_full_password_bytes(self, db_path: str) -> None:
        """verify_password distinguishes passwords that only differ after 72 bytes."""
        long_password = "a" * 72 + "correct-suffix"
        wrong_password = "a" * 72 + "wrong-suffix"
        create_user("longpw", long_password)
        user = get_user("longpw")
        assert user is not None
        assert user.verify_password(long_password) is True
        assert user.verify_password(wrong_password) is False

    def test_delete_user_returns_true(self, db_path: str) -> None:
        """delete_user returns True and removes the user."""
        create_user("eve", "pw")
        assert delete_user("eve") is True
        assert get_user("eve") is None

    def test_delete_user_returns_false_when_missing(self, db_path: str) -> None:
        """delete_user returns False when the user does not exist."""
        assert delete_user("ghost") is False

    def test_timestamps_set_on_create(self, db_path: str) -> None:
        """created_at and updated_at are populated on user creation."""
        before = datetime.now(timezone.utc)
        create_user("frank", "pw")
        after = datetime.now(timezone.utc)

        user = get_user("frank")
        assert user is not None
        assert before <= _ensure_utc(user.created_at) <= after
        assert before <= _ensure_utc(user.updated_at) <= after

    def test_list_users_empty(self, db_path: str) -> None:
        """list_users returns an empty list when no users exist."""
        assert list_users() == []

    def test_list_users_returns_all(self, db_path: str) -> None:
        """list_users returns every created user."""
        create_user("user1", "pw1")
        create_user("user2", "pw2")
        users = list_users()
        usernames = {u.username for u in users}
        assert usernames == {"user1", "user2"}

    def test_update_user_password_succeeds(self, db_path: str) -> None:
        """update_user_password returns True and the new password verifies correctly."""
        create_user("grace", "old-pw")
        result = update_user_password("grace", "new-pw")
        assert result is True
        user = get_user("grace")
        assert user is not None
        assert user.verify_password("new-pw") is True
        assert user.verify_password("old-pw") is False

    def test_update_user_password_advances_updated_at(self, db_path: str) -> None:
        """update_user_password advances updated_at when the password changes."""
        create_user("heidi", "old-pw")
        user = get_user("heidi")
        assert user is not None
        original_updated_at = _ensure_utc(user.updated_at)

        time.sleep(0.01)

        assert update_user_password("heidi", "new-pw") is True

        updated_user = get_user("heidi")
        assert updated_user is not None
        assert _ensure_utc(updated_user.updated_at) > original_updated_at

    def test_update_user_password_returns_false_for_missing(self, db_path: str) -> None:
        """update_user_password returns False when the username does not exist."""
        assert update_user_password("ghost", "pw") is False


class TestClientRedirectUris:
    def test_create_client_with_redirect_uris(self, db_path: str) -> None:
        """create_client stores redirect_uris correctly."""
        client = create_client(
            client_id="redirect-test",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
            redirect_uris=[
                "https://example.com/callback",
                "https://app.example.com/oauth",
            ],
        )
        assert (
            client.redirect_uris
            == "https://example.com/callback,https://app.example.com/oauth"
        )

    def test_get_redirect_uris_list(self, db_path: str) -> None:
        """get_redirect_uris_list returns redirect URIs as a list."""
        create_client(
            client_id="redirect-list-test",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
            redirect_uris=["https://a.com/cb", "https://b.com/cb"],
        )
        client = get_client("redirect-list-test")
        assert client is not None
        assert client.get_redirect_uris_list() == [
            "https://a.com/cb",
            "https://b.com/cb",
        ]

    def test_get_redirect_uris_list_empty(self, db_path: str) -> None:
        """get_redirect_uris_list returns empty list when no redirect_uris configured."""
        create_client(
            client_id="no-redirect-test",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )
        client = get_client("no-redirect-test")
        assert client is not None
        assert client.get_redirect_uris_list() == []


class TestClientScopesAndAudiences:
    def test_get_scopes_list_returns_empty_for_none(self) -> None:
        """get_scopes_list returns an empty list when scopes is None."""
        client = Client(client_id="scopes-none", title="scopes-none", algorithm="HS256")

        assert client.get_scopes_list() == []

    def test_get_scopes_list_returns_empty_for_empty_string(self) -> None:
        """get_scopes_list returns an empty list when scopes is an empty string."""
        client = Client(
            client_id="scopes-empty",
            title="scopes-empty",
            algorithm="HS256",
            scopes="",
        )

        assert client.get_scopes_list() == []

    def test_get_audiences_list_returns_empty_for_none(self) -> None:
        """get_audiences_list returns an empty list when audiences is None."""
        client = Client(
            client_id="audiences-none",
            title="audiences-none",
            algorithm="HS256",
        )

        assert client.get_audiences_list() == []

    def test_get_audiences_list_returns_empty_for_empty_string(self) -> None:
        """get_audiences_list returns an empty list when audiences is an empty string."""
        client = Client(
            client_id="audiences-empty",
            title="audiences-empty",
            algorithm="HS256",
            audiences="",
        )

        assert client.get_audiences_list() == []


class TestClientSecretAndSigningSecret:
    def test_verify_client_secret_returns_false_when_no_secret_stored(
        self, db_path: str
    ) -> None:
        """verify_client_secret returns False when the client has no stored secret."""
        create_client(
            client_id="no-secret-client",
            algorithm=SymmetricAlgorithm.HS256,
            # no client_secret
        )
        client = get_client("no-secret-client")
        assert client is not None
        assert client.verify_client_secret(b"any-secret") is False

    def test_verify_client_secret_accepts_raw_utf8_string(self, db_path: str) -> None:
        """verify_client_secret accepts a raw string when the stored secret came from bytes."""
        create_client(
            client_id="raw-string-secret-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"mysecret",
        )
        client = get_client("raw-string-secret-client")
        assert client is not None
        assert client.verify_client_secret("mysecret") is True

    def test_verify_client_secret_preserves_base64_string_support(
        self, db_path: str
    ) -> None:
        """verify_client_secret still accepts a base64-encoded string input."""
        secret = b"c2VjcmV0Cg=="
        create_client(
            client_id="base64-string-secret-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=secret,
        )
        client = get_client("base64-string-secret-client")
        assert client is not None
        assert client.verify_client_secret(base64.b64encode(secret).decode()) is True

    def test_verify_client_secret_rejects_incorrect_raw_string(
        self, db_path: str
    ) -> None:
        """verify_client_secret returns False for the wrong raw string."""
        create_client(
            client_id="wrong-raw-string-secret-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"mysecret",
        )
        client = get_client("wrong-raw-string-secret-client")
        assert client is not None
        assert client.verify_client_secret("not-mysecret") is False

    def test_get_signing_secret_returns_none_when_not_set(self, db_path: str) -> None:
        """get_signing_secret returns None when no signing secret has been configured."""
        create_client(
            client_id="no-signing-secret-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"client-secret",
            # no signing_secret
        )
        client = get_client("no-signing-secret-client")
        assert client is not None
        assert client.get_signing_secret() is None

    def test_set_and_get_signing_secret_roundtrip(self, db_path: str) -> None:
        """set_signing_secret stores the secret and get_signing_secret retrieves it."""
        create_client(
            client_id="signing-roundtrip-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"client-secret",
        )
        client = get_client("signing-roundtrip-client")
        assert client is not None

        with get_session() as session:
            c = session.get(Client, "signing-roundtrip-client")
            assert c is not None
            c.set_signing_secret(b"my-new-signing-secret")
            session.commit()

        updated = get_client("signing-roundtrip-client")
        assert updated is not None
        assert updated.get_signing_secret() == b"my-new-signing-secret"

    def test_get_signing_secret_fingerprint_returns_none_when_not_set(
        self, db_path: str
    ) -> None:
        """get_signing_secret_fingerprint returns None when no signing secret is set."""
        create_client(
            client_id="no-fingerprint-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"client-secret",
        )
        client = get_client("no-fingerprint-client")
        assert client is not None
        assert client.get_signing_secret_fingerprint() is None

    def test_get_signing_secret_fingerprint_returns_sha256_digest(
        self, db_path: str
    ) -> None:
        """get_signing_secret_fingerprint returns the sha256 fingerprint when set."""
        signing_secret = b"test-signing-secret"
        create_client(
            client_id="fingerprint-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"client-secret",
            signing_secret=signing_secret,
        )
        client = get_client("fingerprint-client")
        assert client is not None

        fingerprint = client.get_signing_secret_fingerprint()
        expected = f"sha256:{hashlib.sha256(signing_secret).hexdigest()}"

        assert fingerprint == expected
