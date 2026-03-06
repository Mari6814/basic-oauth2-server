"""Tests for configuration management."""

from pathlib import Path

import pytest
from jws_algorithms import AsymmetricAlgorithm

from basic_oauth2_server.config import ServerConfig


class TestLoadPrivateKey:
    """Tests for ServerConfig.load_private_key."""

    def test_rsa_key_from_string(self) -> None:
        """RSA key loaded from inline string."""
        config = ServerConfig(rsa_private_key="rsa-key-data")
        result = config.load_private_key(AsymmetricAlgorithm.RS256)
        assert result == b"rsa-key-data"

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
            assert config.load_private_key(alg) == b"rsa-key-data"

    def test_ec_p256_key(self) -> None:
        config = ServerConfig(ec_p256_private_key="ec256-key")
        assert config.load_private_key(AsymmetricAlgorithm.ES256) == b"ec256-key"

    def test_ec_p384_key(self) -> None:
        config = ServerConfig(ec_p384_private_key="ec384-key")
        assert config.load_private_key(AsymmetricAlgorithm.ES384) == b"ec384-key"

    def test_ec_p521_key(self) -> None:
        config = ServerConfig(ec_p521_private_key="ec521-key")
        assert config.load_private_key(AsymmetricAlgorithm.ES512) == b"ec521-key"

    def test_eddsa_key(self) -> None:
        config = ServerConfig(eddsa_private_key="eddsa-key")
        assert config.load_private_key(AsymmetricAlgorithm.EdDSA) == b"eddsa-key"

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
        assert (
            config.load_private_key(AsymmetricAlgorithm.RS256)
            == b"file-rsa-key-content"
        )

    def test_key_from_file_not_found(self, tmp_path: Path) -> None:
        """Raise FileNotFoundError when referenced file doesn't exist."""
        config = ServerConfig(rsa_private_key=f"@{tmp_path / 'missing.pem'}")
        with pytest.raises(FileNotFoundError):
            config.load_private_key(AsymmetricAlgorithm.RS256)

    def test_key_from_base64(self) -> None:
        """Load key from base64-encoded string."""
        config = ServerConfig(rsa_private_key="base64:aGVsbG8=")
        assert config.load_private_key(AsymmetricAlgorithm.RS256) == b"hello"

    def test_key_from_hex(self) -> None:
        """Load key from hex-encoded string."""
        config = ServerConfig(rsa_private_key="0xdeadbeef")
        assert config.load_private_key(AsymmetricAlgorithm.RS256) == b"\xde\xad\xbe\xef"

    def test_result_is_cached(self, tmp_path: Path) -> None:
        """Repeated calls return the same cached object."""
        key_file = tmp_path / "key.pem"
        key_file.write_bytes(b"cached-key")
        config = ServerConfig(rsa_private_key=f"@{key_file}")
        first = config.load_private_key(AsymmetricAlgorithm.RS256)
        # Delete the file — cached result should still be returned
        key_file.unlink()
        second = config.load_private_key(AsymmetricAlgorithm.RS256)
        assert first is second
