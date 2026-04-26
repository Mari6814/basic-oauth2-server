"""Tests for the command-line interface."""

import base64
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pytest import CaptureFixture

from basic_oauth2_server.cli import main
from basic_oauth2_server.db import (
    AuthorizationCode,
    create_authorization_code,
    get_client,
    get_session,
    get_user,
    init_db,
    list_clients,
)


@pytest.fixture(autouse=True)
def app_key() -> None:
    os.environ["APP_KEY"] = base64.b64encode(
        b"test-app-key-1234567890_padded!!"
    ).decode()


@pytest.fixture
def db(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


class TestNoCommand:
    def test_no_command_prints_help_and_returns_1(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(["--db", db])
        assert result == 1
        assert "usage" in capsys.readouterr().out.lower()


class TestClientsCreate:
    def test_create_client_default_algorithm(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(["--db", db, "clients", "create", "-i", "clientA"])
        assert result == 0
        out = capsys.readouterr().out
        assert "OAUTH_CLIENT_ID=clientA" in out
        assert "OAUTH_CLIENT_SECRET=" in out
        assert "JWT_SECRET=" in out
        client = get_client(db, "clientA")
        assert client is not None
        assert client.algorithm == "HS256"

    def test_create_client_with_explicit_secret(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(
            ["--db", db, "clients", "create", "-i", "clientB", "-s", "mysecret"]
        )
        assert result == 0
        out = capsys.readouterr().out
        # Secret was provided by user — should not be echoed back
        assert "OAUTH_CLIENT_SECRET=" not in out

    def test_create_client_with_scopes_and_audiences(self, db: str) -> None:
        result = main(
            [
                "--db",
                db,
                "clients",
                "create",
                "-i",
                "clientC",
                "-c",
                "read",
                "-c",
                "write",
                "-u",
                "https://api.example.com",
            ]
        )
        assert result == 0
        client = get_client(db, "clientC")
        assert client is not None
        assert "read" in client.get_scopes_list()
        assert "write" in client.get_scopes_list()
        assert "https://api.example.com" in client.get_audiences_list()

    def test_create_client_autogenerates_id(self, db: str) -> None:
        result = main(["--db", db, "clients", "create"])
        assert result == 0
        clients = list_clients(db)
        assert len(clients) == 1

    def test_create_client_asymmetric_algorithm(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(
            ["--db", db, "clients", "create", "-i", "clientRS", "-a", "RS256"]
        )
        assert result == 0
        out = capsys.readouterr().out
        # Asymmetric: no signing secret should be printed
        assert "JWT_SECRET=" not in out
        client = get_client(db, "clientRS")
        assert client is not None
        assert client.algorithm == "RS256"


class TestClientsList:
    def test_list_empty(self, db: str, capsys: CaptureFixture[str]) -> None:
        result = main(["--db", db, "clients", "list"])
        assert result == 0
        assert "No clients found" in capsys.readouterr().out

    def test_list_shows_created_clients(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        main(["--db", db, "clients", "create", "-i", "alpha"])
        main(["--db", db, "clients", "create", "-i", "beta"])
        capsys.readouterr()  # flush create output
        result = main(["--db", db, "clients", "list"])
        assert result == 0
        out = capsys.readouterr().out
        assert "alpha" in out
        assert "beta" in out


class TestClientsDelete:
    def test_delete_existing_client(self, db: str, capsys: CaptureFixture[str]) -> None:
        main(["--db", db, "clients", "create", "-i", "to-delete"])
        capsys.readouterr()
        result = main(["--db", db, "clients", "delete", "-d", "to-delete"])
        assert result == 0
        assert "Deleted" in capsys.readouterr().out
        assert get_client(db, "to-delete") is None

    def test_delete_nonexistent_client_returns_1(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(["--db", db, "clients", "delete", "-d", "ghost"])
        assert result == 1
        assert "not found" in capsys.readouterr().err

    def test_no_clients_subcommand_returns_1(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(["--db", db, "clients"])
        assert result == 1


class TestUsersCreate:
    def test_create_user_with_password_flag(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(["--db", db, "users", "create", "-u", "alice", "-p", "secret"])
        assert result == 0
        assert "Created user 'alice'" in capsys.readouterr().out
        user = get_user(db, "alice")
        assert user is not None
        assert user.verify_password("secret")

    def test_create_user_prompts_when_no_password(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("getpass.getpass", return_value="prompted-pw") as mock_getpass:
            result = main(["--db", db, "users", "create", "-u", "bob"])
        assert result == 0
        mock_getpass.assert_called_once()
        assert get_user(db, "bob") is not None

    def test_create_duplicate_user_returns_1(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        main(["--db", db, "users", "create", "-u", "carol", "-p", "pw"])
        capsys.readouterr()
        result = main(["--db", db, "users", "create", "-u", "carol", "-p", "pw2"])
        assert result == 1
        assert "already exists" in capsys.readouterr().err


class TestUsersList:
    def test_list_empty(self, db: str, capsys: CaptureFixture[str]) -> None:
        result = main(["--db", db, "users", "list"])
        assert result == 0
        assert "No users found" in capsys.readouterr().out

    def test_list_shows_created_users(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        main(["--db", db, "users", "create", "-u", "dave", "-p", "pw"])
        main(["--db", db, "users", "create", "-u", "eve", "-p", "pw"])
        capsys.readouterr()
        result = main(["--db", db, "users", "list"])
        assert result == 0
        out = capsys.readouterr().out
        assert "dave" in out
        assert "eve" in out

    def test_list_after_delete_omits_deleted_user(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        main(["--db", db, "users", "create", "-u", "frank", "-p", "pw"])
        main(["--db", db, "users", "create", "-u", "grace", "-p", "pw"])
        main(["--db", db, "users", "delete", "-u", "frank"])
        capsys.readouterr()
        result = main(["--db", db, "users", "list"])
        assert result == 0
        out = capsys.readouterr().out
        assert "frank" not in out
        assert "grace" in out


class TestUsersDelete:
    def test_delete_existing_user(self, db: str, capsys: CaptureFixture[str]) -> None:
        main(["--db", db, "users", "create", "-u", "frank", "-p", "pw"])
        capsys.readouterr()
        result = main(["--db", db, "users", "delete", "-u", "frank"])
        assert result == 0
        assert "Deleted" in capsys.readouterr().out
        assert get_user(db, "frank") is None

    def test_delete_nonexistent_user_returns_1(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(["--db", db, "users", "delete", "-u", "ghost"])
        assert result == 1
        assert "not found" in capsys.readouterr().err


class TestUsersUpdatePassword:
    def test_update_password_with_flag(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        main(["--db", db, "users", "create", "-u", "grace", "-p", "old-pw"])
        capsys.readouterr()
        result = main(
            ["--db", db, "users", "update-password", "-u", "grace", "-p", "new-pw"]
        )
        assert result == 0
        assert "Updated password" in capsys.readouterr().out
        user = get_user(db, "grace")
        assert user is not None
        assert user.verify_password("new-pw")
        assert not user.verify_password("old-pw")

    def test_update_password_prompts_when_no_flag(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        main(["--db", db, "users", "create", "-u", "henry", "-p", "old-pw"])
        capsys.readouterr()
        with patch("getpass.getpass", return_value="prompted-new-pw") as mock_getpass:
            result = main(["--db", db, "users", "update-password", "-u", "henry"])
        assert result == 0
        mock_getpass.assert_called_once()
        user = get_user(db, "henry")
        assert user is not None
        assert user.verify_password("prompted-new-pw")

    def test_update_password_nonexistent_user_returns_1(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(
            ["--db", db, "users", "update-password", "-u", "ghost", "-p", "pw"]
        )
        assert result == 1
        assert "not found" in capsys.readouterr().err

    def test_no_users_subcommand_returns_1(self, db: str) -> None:
        result = main(["--db", db, "users"])
        assert result == 1


class TestAuthCodesPrune:
    def test_prune_deletes_used_and_expired_rows(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        used_code = create_authorization_code(
            db_path=db,
            client_id="client-a",
            user_id="user-a",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
            expires_in=600,
            consent_jti=secrets.token_urlsafe(32),
        )
        expired_code = create_authorization_code(
            db_path=db,
            client_id="client-b",
            user_id="user-b",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
            expires_in=600,
            consent_jti=secrets.token_urlsafe(32),
        )
        active_code = create_authorization_code(
            db_path=db,
            client_id="client-c",
            user_id="user-c",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
            expires_in=600,
            consent_jti=secrets.token_urlsafe(32),
        )

        with get_session(db) as session:
            used = session.get(AuthorizationCode, used_code)
            expired = session.get(AuthorizationCode, expired_code)
            assert used is not None
            assert expired is not None
            used.used = True
            expired.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            session.commit()

        capsys.readouterr()
        result = main(["--db", db, "auth-codes", "prune"])

        assert result == 0
        out = capsys.readouterr().out
        assert "Pruned 2 authorization code rows." in out

        with get_session(db) as session:
            assert session.get(AuthorizationCode, used_code) is None
            assert session.get(AuthorizationCode, expired_code) is None
            assert session.get(AuthorizationCode, active_code) is not None

    def test_prune_with_no_matching_rows(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        create_authorization_code(
            db_path=db,
            client_id="client-active",
            user_id="user-active",
            redirect_uri=None,
            scope="read",
            audience=None,
            state=None,
            code_challenge=None,
            expires_in=600,
            consent_jti=secrets.token_urlsafe(32),
        )

        capsys.readouterr()
        result = main(["--db", db, "auth-codes", "prune"])
        assert result == 0
        assert "Pruned 0 authorization code rows." in capsys.readouterr().out

    def test_no_auth_codes_subcommand_returns_1(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        result = main(["--db", db, "auth-codes"])
        assert result == 1


class TestServeCreateRootClient:
    def test_creates_root_client_default_algorithm(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            result = main(["--db", db, "serve", "--create-default-client"])
        assert result == 0
        out = capsys.readouterr().out
        assert "Created default client 'default'" in out
        assert "OAUTH_DEFAULT_CLIENT_SECRET=" in out
        assert "JWT_SECRET=" in out
        client = get_client(db, "default")
        assert client is not None
        assert client.algorithm == "HS256"

    def test_client_secret_not_printed_when_provided(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-client",
                    "--default-client-secret",
                    "mysecret",
                ]
            )
        assert result == 0
        out = capsys.readouterr().out
        assert "OAUTH_DEFAULT_CLIENT_SECRET=" not in out
        client = get_client(db, "default")
        assert client is not None
        assert client.verify_client_secret(b"mysecret")

    def test_skips_if_root_client_already_exists(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            main(["--db", db, "serve", "--create-default-client"])
        capsys.readouterr()
        with patch("basic_oauth2_server.server.run_server"):
            result = main(["--db", db, "serve", "--create-default-client"])
        assert result == 0
        out = capsys.readouterr().out
        assert "skipping" in out.lower()
        assert "Created" not in out

    def test_symmetric_prints_jwt_secret_and_algorithm(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-client",
                    "--default-client-algorithm",
                    "HS256",
                ]
            )
        assert result == 0
        out = capsys.readouterr().out
        assert "JWT_SECRET=" in out
        assert "JWT_ALGORITHM=HS256" in out

    def test_symmetric_signing_secret_not_printed_when_provided(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-client",
                    "--default-client-algorithm",
                    "HS256",
                    "--default-client-signing-secret",
                    "0xdeadbeef",
                ]
            )
        assert result == 0
        out = capsys.readouterr().out
        assert "JWT_SECRET=" not in out
        client = get_client(db, "default")
        assert client is not None
        assert client.get_signing_secret() == bytes.fromhex("deadbeef")

    def test_asymmetric_no_jwt_secret_printed(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-client",
                    "--default-client-algorithm",
                    "RS256",
                ]
            )
        assert result == 0
        out = capsys.readouterr().out
        assert "JWT_SECRET=" not in out
        client = get_client(db, "default")
        assert client is not None
        assert client.algorithm == "RS256"

    def test_asymmetric_signing_key_loaded_from_file(
        self, db: str, tmp_path: Path, capsys: CaptureFixture[str]
    ) -> None:
        key_file = tmp_path / "fake.pem"
        key_file.write_bytes(
            b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----"
        )
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-client",
                    "--default-client-algorithm",
                    "RS256",
                    "--default-client-signing-secret",
                    str(key_file),
                ]
            )
        assert result == 0
        client = get_client(db, "default")
        assert client is not None
        assert client.get_signing_secret() == key_file.read_bytes()

    def test_with_custom_id_scopes_and_audiences(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-client",
                    "--default-client-id",
                    "myrootclient",
                    "--default-client-scopes",
                    "read write",
                    "--default-client-audiences",
                    "https://api.example.com",
                ]
            )
        assert result == 0
        client = get_client(db, "myrootclient")
        assert client is not None
        assert "read" in client.get_scopes_list()
        assert "write" in client.get_scopes_list()
        assert "https://api.example.com" in client.get_audiences_list()


class TestServeCreateRootUser:
    def test_creates_root_user_with_password_flag(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-user",
                    "--default-password",
                    "secret123",
                ]
            )
        assert result == 0
        out = capsys.readouterr().out
        assert "Created default user 'default'" in out
        user = get_user(db, "default")
        assert user is not None
        assert user.verify_password("secret123")

    def test_creates_root_user_prompts_when_no_password(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("getpass.getpass", return_value="prompted-pw") as mock_getpass:
            with patch("basic_oauth2_server.server.run_server"):
                result = main(["--db", db, "serve", "--create-default-user"])
        assert result == 0
        mock_getpass.assert_called_once()
        user = get_user(db, "default")
        assert user is not None
        assert user.verify_password("prompted-pw")

    def test_updates_existing_user_password(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-user",
                    "--default-password",
                    "old-pw",
                ]
            )
        capsys.readouterr()
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-user",
                    "--default-password",
                    "new-pw",
                ]
            )
        assert result == 0
        out = capsys.readouterr().out
        assert "Updated default user 'default'" in out
        user = get_user(db, "default")
        assert user is not None
        assert user.verify_password("new-pw")
        assert not user.verify_password("old-pw")

    def test_updates_existing_user_prompts_when_no_password(
        self, db: str, capsys: CaptureFixture[str]
    ) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-user",
                    "--default-password",
                    "old-pw",
                ]
            )
        capsys.readouterr()
        with patch("getpass.getpass", return_value="new-pw-prompted") as mock_getpass:
            with patch("basic_oauth2_server.server.run_server"):
                result = main(["--db", db, "serve", "--create-default-user"])
        assert result == 0
        mock_getpass.assert_called_once()
        user = get_user(db, "default")
        assert user is not None
        assert user.verify_password("new-pw-prompted")
        assert not user.verify_password("old-pw")

    def test_with_custom_username(self, db: str, capsys: CaptureFixture[str]) -> None:
        with patch("basic_oauth2_server.server.run_server"):
            result = main(
                [
                    "--db",
                    db,
                    "serve",
                    "--create-default-user",
                    "--default-username",
                    "admin",
                    "--default-password",
                    "adminpass",
                ]
            )
        assert result == 0
        user = get_user(db, "admin")
        assert user is not None
        assert user.verify_password("adminpass")
