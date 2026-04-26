"""Tests for configuration management."""

import os
from pathlib import Path

import pytest
from jws_algorithms import AsymmetricAlgorithm
from pytest import MonkeyPatch

from basic_oauth2_server.config import (
    AdminConfig,
    ServerConfig,
    ensure_app_key,
    get_app_key,
)


class TestLoadPrivateKey:
    """Tests for ServerConfig.load_private_key."""

    def test_rsa_key_from_string(self) -> None:
        """RSA key loaded from inline string."""
        config = ServerConfig(rsa_private_key="rsa-key-data")
        key, kid = config.load_private_key(AsymmetricAlgorithm.RS256)
        assert key == b"rsa-key-data"
        assert kid is None

    def test_rsa_key_shared_across_rsa_algorithms(self) -> None:
        """All RSA-based algorithms use the same rsa_private_key."""
        config = ServerConfig(rsa_private_key="rsa-key-data")
        for alg in (
            AsymmetricAlgorithm.RS256,
            AsymmetricAlgorithm.RS384,
            AsymmetricAlgorithm.RS512,
            AsymmetricAlgorithm.PS256,
            AsymmetricAlgorithm.PS384,
            AsymmetricAlgorithm.PS512,
        ):
            key, kid = config.load_private_key(alg)
            assert key == b"rsa-key-data"
            assert kid is None

    def test_ec_p256_key(self) -> None:
        config = ServerConfig(ec_p256_private_key="ec256-key")
        key, kid = config.load_private_key(AsymmetricAlgorithm.ES256)
        assert key == b"ec256-key"
        assert kid is None

    def test_ec_p384_key(self) -> None:
        config = ServerConfig(ec_p384_private_key="ec384-key")
        key, kid = config.load_private_key(AsymmetricAlgorithm.ES384)
        assert key == b"ec384-key"
        assert kid is None

    def test_ec_p521_key(self) -> None:
        config = ServerConfig(ec_p521_private_key="ec521-key")
        key, kid = config.load_private_key(AsymmetricAlgorithm.ES512)
        assert key == b"ec521-key"
        assert kid is None

    def test_eddsa_key(self) -> None:
        config = ServerConfig(eddsa_private_key="eddsa-key")
        key, kid = config.load_private_key(AsymmetricAlgorithm.EdDSA)
        assert key == b"eddsa-key"
        assert kid is None

    def test_missing_key_raises(self) -> None:
        """Raise ValueError when no key is configured for the algorithm."""
        config = ServerConfig()
        with pytest.raises(ValueError, match="No private key configured"):
            config.load_private_key(AsymmetricAlgorithm.RS256)

    def test_key_from_file(self, tmp_path: Path) -> None:
        """Load key from a file using the @ prefix."""
        key_file = tmp_path / "rsa.pem"
        key_file.write_bytes(b"file-rsa-key-content")
        config = ServerConfig(rsa_private_key=f"@{key_file}")
        key, kid = config.load_private_key(AsymmetricAlgorithm.RS256)
        assert key == b"file-rsa-key-content"
        assert kid is None

    def test_key_from_file_not_found(self, tmp_path: Path) -> None:
        """Raise FileNotFoundError when referenced file doesn't exist."""
        config = ServerConfig(rsa_private_key=f"@{tmp_path / 'missing.pem'}")
        with pytest.raises(FileNotFoundError):
            config.load_private_key(AsymmetricAlgorithm.RS256)

    def test_key_from_base64(self) -> None:
        """Load key from base64-encoded string."""
        config = ServerConfig(rsa_private_key="base64:aGVsbG8=")
        key, kid = config.load_private_key(AsymmetricAlgorithm.RS256)
        assert key == b"hello"
        assert kid is None

    def test_key_from_hex(self) -> None:
        """Load key from hex-encoded string."""
        config = ServerConfig(rsa_private_key="0xdeadbeef")
        key, kid = config.load_private_key(AsymmetricAlgorithm.RS256)
        assert key == b"\xde\xad\xbe\xef"
        assert kid is None

    def test_result_is_cached(self, tmp_path: Path) -> None:
        """Repeated calls return the same cached object."""
        key_file = tmp_path / "key.pem"
        key_file.write_bytes(b"cached-key")
        config = ServerConfig(rsa_private_key=f"@{key_file}")
        first, kid1 = config.load_private_key(AsymmetricAlgorithm.RS256)
        # Delete the file — cached result should still be returned
        key_file.unlink()
        second, kid2 = config.load_private_key(AsymmetricAlgorithm.RS256)
        assert first is second
        assert kid1 == kid2

    def test_returns_key_id(self) -> None:
        """Returns the correct key id for each algorithm family."""
        config = ServerConfig(
            rsa_private_key="rsa-key-data",
            rsa_key_id="rsa-kid",
            ec_p256_private_key="ec256-key",
            ec_p256_key_id="ec256-kid",
            ec_p384_private_key="ec384-key",
            ec_p384_key_id="ec384-kid",
            ec_p521_private_key="ec521-key",
            ec_p521_key_id="ec521-kid",
            eddsa_private_key="eddsa-key",
            eddsa_key_id="eddsa-kid",
        )
        key, kid = config.load_private_key(AsymmetricAlgorithm.RS256)
        assert key == b"rsa-key-data"
        assert kid == "rsa-kid"
        key, kid = config.load_private_key(AsymmetricAlgorithm.ES256)
        assert key == b"ec256-key"
        assert kid == "ec256-kid"
        key, kid = config.load_private_key(AsymmetricAlgorithm.ES384)
        assert key == b"ec384-key"
        assert kid == "ec384-kid"
        key, kid = config.load_private_key(AsymmetricAlgorithm.ES512)
        assert key == b"ec521-key"
        assert kid == "ec521-kid"
        key, kid = config.load_private_key(AsymmetricAlgorithm.EdDSA)
        assert key == b"eddsa-key"
        assert kid == "eddsa-kid"


class TestServerConfigFromEnv:
    def test_defaults_when_no_env_vars(self, monkeypatch: MonkeyPatch) -> None:
        """from_env returns defaults when no relevant env vars are set."""
        for var in (
            "OAUTH_HOST",
            "OAUTH_PORT",
            "OAUTH_DB_PATH",
            "APP_URL",
            "OAUTH_RSA_PRIVATE_KEY",
            "OAUTH_EC_P256_PRIVATE_KEY",
            "OAUTH_EC_P384_PRIVATE_KEY",
            "OAUTH_EC_P521_PRIVATE_KEY",
            "OAUTH_EDDSA_PRIVATE_KEY",
            "OAUTH_RSA_KEY_ID",
            "OAUTH_EC_P256_KEY_ID",
            "OAUTH_EC_P384_KEY_ID",
            "OAUTH_EC_P521_KEY_ID",
            "OAUTH_EDDSA_KEY_ID",
            "OAUTH_TOKEN_EXPIRES_IN",
        ):
            monkeypatch.delenv(var, raising=False)
        config = ServerConfig.from_env()
        assert config.host == "localhost"
        assert config.port == 8080
        assert config.db_path == "./oauth.db"
        assert config.app_url == "http://localhost:8080"
        assert config.token_expires_in == 3600

    def test_reads_env_vars(self, monkeypatch: MonkeyPatch) -> None:
        """from_env picks up configured environment variables."""
        monkeypatch.setenv("OAUTH_HOST", "0.0.0.0")
        monkeypatch.setenv("OAUTH_PORT", "9000")
        monkeypatch.setenv("OAUTH_DB_PATH", "/tmp/mydb.db")
        monkeypatch.setenv("APP_URL", "https://auth.example.com")
        monkeypatch.setenv("OAUTH_RSA_PRIVATE_KEY", "my-rsa-key")
        monkeypatch.setenv("OAUTH_TOKEN_EXPIRES_IN", "7200")
        config = ServerConfig.from_env()
        assert config.host == "0.0.0.0"
        assert config.port == 9000
        assert config.db_path == "/tmp/mydb.db"
        assert config.app_url == "https://auth.example.com"
        assert config.rsa_private_key == "my-rsa-key"
        assert config.token_expires_in == 7200

    def test_rejects_non_absolute_app_url(self, monkeypatch: MonkeyPatch) -> None:
        """from_env rejects APP_URL values that are not absolute URIs."""
        monkeypatch.setenv("APP_URL", "/relative/path")
        with pytest.raises(ValueError, match="absolute URI"):
            ServerConfig.from_env()

    @pytest.mark.parametrize(
        "app_url",
        [
            "https://auth.example.com",
            "http://localhost:8080",
            "https://example.com/oauth2",
        ],
    )
    def test_accepts_absolute_app_url(self, app_url: str) -> None:
        """Direct construction accepts valid absolute URLs."""
        config = ServerConfig(app_url=app_url)
        assert config.app_url == app_url

    @pytest.mark.parametrize(
        "app_url",
        ["", " ", "https://example.com ", "example.com", "/oauth"],
    )
    def test_rejects_invalid_app_url(self, app_url: str) -> None:
        """Direct construction rejects malformed or non-absolute URIs."""
        with pytest.raises(ValueError, match="app_url"):
            ServerConfig(app_url=app_url)

    def test_rejects_none_app_url(self) -> None:
        """Runtime None must not be accepted for app_url."""
        with pytest.raises(ValueError, match="app_url"):
            ServerConfig(app_url=None)  # type: ignore[arg-type]


class TestAdminConfigFromEnv:
    def test_defaults_when_no_env_vars(self, monkeypatch: MonkeyPatch) -> None:
        """from_env returns defaults when no relevant env vars are set."""
        for var in ("APP_URL", "OAUTH_ADMIN_HOST", "OAUTH_ADMIN_PORT", "OAUTH_DB_PATH"):
            monkeypatch.delenv(var, raising=False)
        config = AdminConfig.from_env()
        assert config.host == "localhost"
        assert config.port == 8081
        assert config.db_path == "./oauth.db"
        assert config.app_url == "http://localhost:8080"

    def test_reads_env_vars(self, monkeypatch: MonkeyPatch) -> None:
        """from_env picks up configured environment variables."""
        monkeypatch.setenv("APP_URL", "https://app.example.com")
        monkeypatch.setenv("OAUTH_ADMIN_HOST", "0.0.0.0")
        monkeypatch.setenv("OAUTH_ADMIN_PORT", "9090")
        monkeypatch.setenv("OAUTH_DB_PATH", "/data/admin.db")
        config = AdminConfig.from_env()
        assert config.app_url == "https://app.example.com"
        assert config.host == "0.0.0.0"
        assert config.port == 9090
        assert config.db_path == "/data/admin.db"

    def test_rejects_non_absolute_app_url(self, monkeypatch: MonkeyPatch) -> None:
        """from_env rejects APP_URL values that are not absolute URIs."""
        monkeypatch.setenv("APP_URL", "relative")
        with pytest.raises(ValueError, match="absolute URI"):
            AdminConfig.from_env()


class TestEnsureAppKey:
    def test_does_nothing_when_app_key_already_set(
        self, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("APP_KEY", "existing-key")
        ensure_app_key()
        assert os.environ["APP_KEY"] == "existing-key"

    def test_generates_and_prints_key_when_absent(
        self, monkeypatch: MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("APP_KEY", raising=False)
        ensure_app_key()
        key = os.environ.get("APP_KEY")
        assert key is not None
        captured = capsys.readouterr()
        assert f"APP_KEY={key}" in captured.out
        assert "WARNING" in captured.err


class TestGetAppKey:
    def test_raises_when_not_set(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.delenv("APP_KEY", raising=False)
        with pytest.raises(ValueError, match="APP_KEY"):
            get_app_key()

    def test_returns_non_base64_value_as_utf8(self, monkeypatch: MonkeyPatch) -> None:
        # 32-character plain text — not valid base64, so it falls back to UTF-8 encoding
        monkeypatch.setenv("APP_KEY", "not!!!base64_but_long_enough!!!!")
        key = get_app_key()
        assert key == b"not!!!base64_but_long_enough!!!!"

    def test_raises_if_key_too_short(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setenv("APP_KEY", "not!!!base64")
        with pytest.raises(ValueError, match="at least 32 bytes"):
            get_app_key()
