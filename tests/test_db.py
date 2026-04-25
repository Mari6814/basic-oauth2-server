"""Tests for database models and auto-managed timestamp columns."""

import base64
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.db import (
    Client,
    AuthorizationCode,
    create_client,
    create_authorization_code,
    create_user,
    delete_user,
    get_client,
    get_authorization_code,
    get_session,
    get_user,
    init_db,
    list_users,
    update_user_password,
)


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = base64.b64encode(b"test-app-key-1234567890_padded!!").decode()


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware in UTC for consistent comparisons."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


class TestClientTimestamps:
    def test_created_at_set_on_insert(self, db_path: str) -> None:
        """created_at is populated automatically when a client is first created."""
        before = datetime.now(timezone.utc)
        create_client(
            db_path=db_path,
            client_id="c1",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )
        after = datetime.now(timezone.utc)

        client = get_client(db_path, "c1")
        assert client is not None
        assert before <= _ensure_utc(client.created_at) <= after

    def test_updated_at_set_on_insert(self, db_path: str) -> None:
        """updated_at is populated automatically on initial insert."""
        before = datetime.now(timezone.utc)
        create_client(
            db_path=db_path,
            client_id="c2",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )
        after = datetime.now(timezone.utc)

        client = get_client(db_path, "c2")
        assert client is not None
        assert before <= _ensure_utc(client.updated_at) <= after

    def test_updated_at_changes_on_update(self, db_path: str) -> None:
        """updated_at advances when the record is modified."""
        create_client(
            db_path=db_path,
            client_id="c3",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )

        client = get_client(db_path, "c3")
        assert client is not None
        original_updated_at = client.updated_at

        time.sleep(0.01)

        with get_session(db_path) as session:
            c = session.get(Client, "c3")
            assert c is not None
            c.scopes = "read,write"
            session.commit()

        updated = get_client(db_path, "c3")
        assert updated is not None
        assert updated.updated_at >= original_updated_at

    def test_created_at_unchanged_on_update(self, db_path: str) -> None:
        """created_at must not change when the record is updated."""
        create_client(
            db_path=db_path,
            client_id="c4",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )

        client = get_client(db_path, "c4")
        assert client is not None
        original_created_at = client.created_at

        time.sleep(0.01)

        with get_session(db_path) as session:
            c = session.get(Client, "c4")
            assert c is not None
            c.scopes = "admin"
            session.commit()

        updated = get_client(db_path, "c4")
        assert updated is not None
        assert updated.created_at == original_created_at


class TestAuthorizationCodeTimestamps:
    def test_created_at_set_on_insert(self, db_path: str) -> None:
        """created_at is populated automatically when an authorization code is created."""
        before = datetime.now(timezone.utc)
        code = create_authorization_code(
            db_path=db_path,
            client_id="client1",
            user_id="user1",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
        )
        after = datetime.now(timezone.utc)

        record = get_authorization_code(db_path, code)
        assert record is not None
        assert before <= _ensure_utc(record.created_at) <= after

    def test_updated_at_set_on_insert(self, db_path: str) -> None:
        """updated_at is populated automatically on initial insert."""
        before = datetime.now(timezone.utc)
        code = create_authorization_code(
            db_path=db_path,
            client_id="client1",
            user_id="user1",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
        )
        after = datetime.now(timezone.utc)

        record = get_authorization_code(db_path, code)
        assert record is not None
        assert before <= _ensure_utc(record.updated_at) <= after

    def test_updated_at_changes_on_update(self, db_path: str) -> None:
        """updated_at advances when an authorization code record is modified."""
        code = create_authorization_code(
            db_path=db_path,
            client_id="client1",
            user_id="user1",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
        )
        record = get_authorization_code(db_path, code)
        assert record is not None
        original_updated_at = record.updated_at

        time.sleep(0.01)

        with get_session(db_path) as session:
            auth_code = session.get(AuthorizationCode, code)
            assert auth_code is not None
            auth_code.used = True
            session.commit()

        with get_session(db_path) as session:
            updated = session.get(AuthorizationCode, code)
            assert updated is not None
            assert updated.updated_at >= original_updated_at


class TestUser:
    def test_create_user_stores_hashed_password(self, db_path: str) -> None:
        """create_user persists the user and stores a bcrypt hash, not the plaintext."""
        user = create_user(db_path, "alice", "s3cr3t")
        assert user.username == "alice"
        assert user.password_hash != "s3cr3t"
        assert user.password_hash.startswith("$2b$")

    def test_get_user_returns_user(self, db_path: str) -> None:
        """get_user returns the created user by username."""
        create_user(db_path, "bob", "pass123")
        user = get_user(db_path, "bob")
        assert user is not None
        assert user.username == "bob"

    def test_get_user_returns_none_for_missing(self, db_path: str) -> None:
        """get_user returns None when the username does not exist."""
        assert get_user(db_path, "nobody") is None

    def test_verify_password_correct(self, db_path: str) -> None:
        """verify_password returns True for the correct password."""
        create_user(db_path, "carol", "correct-horse")
        user = get_user(db_path, "carol")
        assert user is not None
        assert user.verify_password("correct-horse") is True

    def test_verify_password_wrong(self, db_path: str) -> None:
        """verify_password returns False for an incorrect password."""
        create_user(db_path, "dave", "correct-horse")
        user = get_user(db_path, "dave")
        assert user is not None
        assert user.verify_password("wrong-password") is False

    def test_delete_user_returns_true(self, db_path: str) -> None:
        """delete_user returns True and removes the user."""
        create_user(db_path, "eve", "pw")
        assert delete_user(db_path, "eve") is True
        assert get_user(db_path, "eve") is None

    def test_delete_user_returns_false_when_missing(self, db_path: str) -> None:
        """delete_user returns False when the user does not exist."""
        assert delete_user(db_path, "ghost") is False

    def test_timestamps_set_on_create(self, db_path: str) -> None:
        """created_at and updated_at are populated on user creation."""
        before = datetime.now(timezone.utc)
        create_user(db_path, "frank", "pw")
        after = datetime.now(timezone.utc)

        user = get_user(db_path, "frank")
        assert user is not None
        assert before <= _ensure_utc(user.created_at) <= after
        assert before <= _ensure_utc(user.updated_at) <= after

    def test_list_users_empty(self, db_path: str) -> None:
        """list_users returns an empty list when no users exist."""
        assert list_users(db_path) == []

    def test_list_users_returns_all(self, db_path: str) -> None:
        """list_users returns every created user."""
        create_user(db_path, "user1", "pw1")
        create_user(db_path, "user2", "pw2")
        users = list_users(db_path)
        usernames = {u.username for u in users}
        assert usernames == {"user1", "user2"}

    def test_update_user_password_succeeds(self, db_path: str) -> None:
        """update_user_password returns True and the new password verifies correctly."""
        create_user(db_path, "grace", "old-pw")
        result = update_user_password(db_path, "grace", "new-pw")
        assert result is True
        user = get_user(db_path, "grace")
        assert user is not None
        assert user.verify_password("new-pw") is True
        assert user.verify_password("old-pw") is False

    def test_update_user_password_returns_false_for_missing(self, db_path: str) -> None:
        """update_user_password returns False when the username does not exist."""
        assert update_user_password(db_path, "ghost", "pw") is False


class TestClientRedirectUris:
    def test_create_client_with_redirect_uris(self, db_path: str) -> None:
        """create_client stores redirect_uris correctly."""
        client = create_client(
            db_path=db_path,
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
            db_path=db_path,
            client_id="redirect-list-test",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
            redirect_uris=["https://a.com/cb", "https://b.com/cb"],
        )
        client = get_client(db_path, "redirect-list-test")
        assert client is not None
        assert client.get_redirect_uris_list() == [
            "https://a.com/cb",
            "https://b.com/cb",
        ]

    def test_get_redirect_uris_list_empty(self, db_path: str) -> None:
        """get_redirect_uris_list returns empty list when no redirect_uris configured."""
        create_client(
            db_path=db_path,
            client_id="no-redirect-test",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"secret",
        )
        client = get_client(db_path, "no-redirect-test")
        assert client is not None
        assert client.get_redirect_uris_list() == []


class TestClientSecretAndSigningSecret:
    def test_verify_client_secret_returns_false_when_no_secret_stored(
        self, db_path: str
    ) -> None:
        """verify_client_secret returns False when the client has no stored secret."""
        create_client(
            db_path=db_path,
            client_id="no-secret-client",
            algorithm=SymmetricAlgorithm.HS256,
            # no client_secret
        )
        client = get_client(db_path, "no-secret-client")
        assert client is not None
        assert client.verify_client_secret(b"any-secret") is False

    def test_get_signing_secret_returns_none_when_not_set(self, db_path: str) -> None:
        """get_signing_secret returns None when no signing secret has been configured."""
        create_client(
            db_path=db_path,
            client_id="no-signing-secret-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"client-secret",
            # no signing_secret
        )
        client = get_client(db_path, "no-signing-secret-client")
        assert client is not None
        assert client.get_signing_secret() is None

    def test_set_and_get_signing_secret_roundtrip(self, db_path: str) -> None:
        """set_signing_secret stores the secret and get_signing_secret retrieves it."""
        create_client(
            db_path=db_path,
            client_id="signing-roundtrip-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"client-secret",
        )
        client = get_client(db_path, "signing-roundtrip-client")
        assert client is not None

        with get_session(db_path) as session:
            c = session.get(Client, "signing-roundtrip-client")
            assert c is not None
            c.set_signing_secret(b"my-new-signing-secret")
            session.commit()

        updated = get_client(db_path, "signing-roundtrip-client")
        assert updated is not None
        assert updated.get_signing_secret() == b"my-new-signing-secret"

    def test_get_signing_secret_fingerprint_returns_none_when_not_set(
        self, db_path: str
    ) -> None:
        """get_signing_secret_fingerprint returns None when no signing secret is set."""
        create_client(
            db_path=db_path,
            client_id="no-fingerprint-client",
            algorithm=SymmetricAlgorithm.HS256,
            client_secret=b"client-secret",
        )
        client = get_client(db_path, "no-fingerprint-client")
        assert client is not None
        assert client.get_signing_secret_fingerprint() is None
