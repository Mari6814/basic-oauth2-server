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
    get_client,
    get_authorization_code,
    get_session,
    init_db,
)


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = base64.b64encode(b"test-app-key-1234567890").decode()


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

        updated = get_authorization_code(db_path, code)
        assert updated is not None
        assert updated.updated_at >= original_updated_at
