"""Tests for the JWKS endpoint and jwks module."""

import base64
import os
from collections.abc import Generator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from fastapi.testclient import TestClient

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import init_db
from basic_oauth2_server.jwks import build_jwks
from basic_oauth2_server.server import create_app


def _pem(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey,
) -> str:
    """Serialize a private key to PEM string."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def temp_db(tmp_path: Path) -> Generator[str, None, None]:
    """Create a temporary database for testing."""
    db_path = tmp_path / "test_oauth.db"
    os.environ["APP_KEY"] = base64.b64encode(b"test-app-key-1234567890").decode()
    init_db(str(db_path))
    yield str(db_path)


@pytest.fixture
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def ec_p256_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def ec_p384_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


@pytest.fixture
def ec_p521_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP521R1())


@pytest.fixture
def eddsa_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


class TestBuildJwks:
    def test_no_keys_configured(self) -> None:
        config = ServerConfig()
        result = build_jwks(config)
        assert result == {"keys": []}

    def test_rsa_key(self, rsa_key: rsa.RSAPrivateKey) -> None:
        config = ServerConfig(rsa_private_key=_pem(rsa_key))
        result = build_jwks(config)
        assert len(result["keys"]) == 1
        jwk = result["keys"][0]
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert "alg" not in jwk
        assert "n" in jwk
        assert "e" in jwk
        assert "kid" not in jwk

    def test_rsa_key_with_kid(self, rsa_key: rsa.RSAPrivateKey) -> None:
        config = ServerConfig(
            rsa_private_key=_pem(rsa_key),
            rsa_key_id="my-rsa-key",
        )
        result = build_jwks(config)
        assert result["keys"][0]["kid"] == "my-rsa-key"

    def test_ec_p256_key(self, ec_p256_key: ec.EllipticCurvePrivateKey) -> None:
        config = ServerConfig(ec_p256_private_key=_pem(ec_p256_key))
        result = build_jwks(config)
        assert len(result["keys"]) == 1
        jwk = result["keys"][0]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["alg"] == "ES256"
        assert "x" in jwk
        assert "y" in jwk

    def test_ec_p384_key(self, ec_p384_key: ec.EllipticCurvePrivateKey) -> None:
        config = ServerConfig(ec_p384_private_key=_pem(ec_p384_key))
        result = build_jwks(config)
        assert len(result["keys"]) == 1
        jwk = result["keys"][0]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-384"
        assert jwk["alg"] == "ES384"

    def test_ec_p521_key(self, ec_p521_key: ec.EllipticCurvePrivateKey) -> None:
        config = ServerConfig(ec_p521_private_key=_pem(ec_p521_key))
        result = build_jwks(config)
        assert len(result["keys"]) == 1
        jwk = result["keys"][0]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-521"
        assert jwk["alg"] == "ES512"

    def test_eddsa_key(self, eddsa_key: ed25519.Ed25519PrivateKey) -> None:
        config = ServerConfig(eddsa_private_key=_pem(eddsa_key))
        result = build_jwks(config)
        assert len(result["keys"]) == 1
        jwk = result["keys"][0]
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["alg"] == "EdDSA"
        assert "x" in jwk

    def test_multiple_keys(
        self,
        rsa_key: rsa.RSAPrivateKey,
        ec_p256_key: ec.EllipticCurvePrivateKey,
        eddsa_key: ed25519.Ed25519PrivateKey,
    ) -> None:
        config = ServerConfig(
            rsa_private_key=_pem(rsa_key),
            rsa_key_id="rsa-1",
            ec_p256_private_key=_pem(ec_p256_key),
            ec_p256_key_id="ec-1",
            eddsa_private_key=_pem(eddsa_key),
            eddsa_key_id="eddsa-1",
        )
        result = build_jwks(config)
        assert len(result["keys"]) == 3
        ktys = {k["kty"] for k in result["keys"]}
        assert ktys == {"RSA", "EC", "OKP"}
        kids = {k["kid"] for k in result["keys"]}
        assert kids == {"rsa-1", "ec-1", "eddsa-1"}

    def test_invalid_key_is_skipped(self) -> None:
        config = ServerConfig(rsa_private_key="not-a-valid-pem")
        result = build_jwks(config)
        assert result == {"keys": []}


class TestJwksEndpoint:
    """Tests for the /.well-known/jwks.json endpoint."""

    def test_empty_jwks(self, temp_db: str) -> None:
        config = ServerConfig(db_path=temp_db)
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        assert response.json() == {"keys": []}
        assert response.headers["content-type"] == "application/json"

    def test_jwks_with_rsa_key(self, temp_db: str, rsa_key: rsa.RSAPrivateKey) -> None:
        config = ServerConfig(
            db_path=temp_db,
            rsa_private_key=_pem(rsa_key),
            rsa_key_id="test-rsa",
        )
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        data = response.json()
        assert len(data["keys"]) == 1
        assert data["keys"][0]["kid"] == "test-rsa"
        assert data["keys"][0]["kty"] == "RSA"
        assert "alg" not in data["keys"][0]

    def test_jwks_with_multiple_keys(
        self,
        temp_db: str,
        rsa_key: rsa.RSAPrivateKey,
        ec_p256_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        config = ServerConfig(
            db_path=temp_db,
            rsa_private_key=_pem(rsa_key),
            ec_p256_private_key=_pem(ec_p256_key),
        )
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        data = response.json()
        assert len(data["keys"]) == 2
