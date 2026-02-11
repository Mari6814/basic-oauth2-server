"""Tests for the OAuth server."""

import os
from pathlib import Path
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import create_client, init_db
from basic_oauth2_server.server import create_app


@pytest.fixture
def temp_db(tmp_path: Path) -> Generator[str, None, None]:
    """Create a temporary database for testing using pytest's tmp_path."""
    db_path = tmp_path / "test_oauth.db"

    # Set APP_KEY for encryption
    os.environ["APP_KEY"] = "dGVzdGtleTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA=="

    init_db(str(db_path))
    yield str(db_path)


@pytest.fixture
def client_with_db(temp_db: str) -> TestClient:
    """Create a test client with a temporary database."""
    # Create a test OAuth client
    create_client(
        db_path=temp_db,
        client_id="test-client",
        secret=b"test-secret",
        algorithm="HS256",
        signing_secret=b"test-signing-secret-1234567890",
        scopes=["read", "write"],
        audiences=["https://api.test.com"],
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
    )
    app = create_app(config)
    return TestClient(app)


def test_token_endpoint_success(client_with_db: TestClient) -> None:
    """Test successful token request."""
    response = client_with_db.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] == 3600


def test_token_endpoint_with_scope(client_with_db: TestClient) -> None:
    """Test token request with valid scope."""
    response = client_with_db.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "scope": "read write",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "read write"


def test_request_subset_of_allowed_scopes(temp_db: str) -> None:
    """A client may request a subset of its configured scopes."""
    # create client with three allowed scopes
    create_client(
        db_path=temp_db,
        client_id="subset-client",
        secret=b"subset-secret",
        algorithm="HS256",
        signing_secret=b"subset-signing-secret-000",
        scopes=["read", "write", "admin"],
    )

    config = ServerConfig(host="localhost", port=8080, db_path=temp_db)
    app = create_app(config)
    tc = TestClient(app)

    resp = tc.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "subset-client",
            "client_secret": "subset-secret",
            "scope": "read write",
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data.get("scope") == "read write"


def test_token_endpoint_invalid_scope(client_with_db: TestClient) -> None:
    """Test token request with invalid scope."""
    response = client_with_db.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "scope": "admin",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "invalid_scope"


def test_token_endpoint_invalid_client(client_with_db: TestClient) -> None:
    """Test token request with invalid client."""
    response = client_with_db.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "nonexistent",
            "client_secret": "wrong",
        },
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "invalid_client"


def test_token_endpoint_wrong_secret(client_with_db: TestClient) -> None:
    """Test token request with wrong secret."""
    response = client_with_db.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": "wrong-secret",
        },
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "invalid_client"


def test_token_endpoint_unsupported_grant_type(client_with_db: TestClient) -> None:
    """Test token request with unsupported grant type."""
    response = client_with_db.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "unsupported_grant_type"


def test_token_endpoint_with_audience(client_with_db: TestClient) -> None:
    """Test token request with valid audience."""
    response = client_with_db.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "audience": "https://api.test.com",
        },
    )

    assert response.status_code == 200


def test_request_one_of_allowed_audiences(temp_db: str) -> None:
    """A client may request any single audience from its configured list."""
    # create client with two allowed audiences
    create_client(
        db_path=temp_db,
        client_id="audience-client",
        secret=b"audience-secret",
        algorithm="HS256",
        signing_secret=b"audience-signing-secret-000",
        audiences=["https://api.a.example", "https://api.b.example"],
    )

    config = ServerConfig(host="localhost", port=8080, db_path=temp_db)
    app = create_app(config)
    tc = TestClient(app)

    resp = tc.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "audience-client",
            "client_secret": "audience-secret",
            "audience": "https://api.b.example",
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data

    # decode payload and verify aud claim matches the requested audience
    import base64
    import json

    payload_b64 = data["access_token"].split(".")[1]
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    assert payload.get("aud") == "https://api.b.example"


def test_token_endpoint_invalid_audience(client_with_db: TestClient) -> None:
    """Test token request with invalid audience."""
    response = client_with_db.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "audience": "https://wrong.com",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "invalid_target"


# Test keys directory
KEYS_DIR = Path(__file__).parent / "keys"


@pytest.fixture
def client_with_rsa(temp_db: str) -> TestClient:
    """Create a test client using RS256 algorithm."""
    create_client(
        db_path=temp_db,
        client_id="rsa-client",
        secret=b"rsa-secret",
        algorithm="RS256",
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
        rsa_private_key=f"@{KEYS_DIR / 'rsa-private.pem'}",
    )
    app = create_app(config)
    return TestClient(app)


@pytest.fixture
def client_with_es256(temp_db: str) -> TestClient:
    """Create a test client using ES256 algorithm."""
    create_client(
        db_path=temp_db,
        client_id="es256-client",
        secret=b"es256-secret",
        algorithm="ES256",
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
        ec_p256_private_key=f"@{KEYS_DIR / 'es256-private.pem'}",
    )
    app = create_app(config)
    return TestClient(app)


@pytest.fixture
def client_with_es384(temp_db: str) -> TestClient:
    """Create a test client using ES384 algorithm."""
    create_client(
        db_path=temp_db,
        client_id="es384-client",
        secret=b"es384-secret",
        algorithm="ES384",
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
        ec_p384_private_key=f"@{KEYS_DIR / 'es384-private.pem'}",
    )
    app = create_app(config)
    return TestClient(app)


@pytest.fixture
def client_with_es512(temp_db: str) -> TestClient:
    """Create a test client using ES512 algorithm."""
    create_client(
        db_path=temp_db,
        client_id="es512-client",
        secret=b"es512-secret",
        algorithm="ES512",
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
        ec_p521_private_key=f"@{KEYS_DIR / 'es512-private.pem'}",
    )
    app = create_app(config)
    return TestClient(app)


@pytest.fixture
def client_with_eddsa(temp_db: str) -> TestClient:
    """Create a test client using EdDSA algorithm."""
    create_client(
        db_path=temp_db,
        client_id="eddsa-client",
        secret=b"eddsa-secret",
        algorithm="EdDSA",
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
        eddsa_private_key=f"@{KEYS_DIR / 'ed25519-private.pem'}",
    )
    app = create_app(config)
    return TestClient(app)


def test_token_rsa_algorithm(client_with_rsa: TestClient) -> None:
    """Test token generation with RS256."""
    response = client_with_rsa.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "rsa-client",
            "client_secret": "rsa-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    # Verify JWT header indicates RS256
    import base64
    import json

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "RS256"


def test_token_es256_algorithm(client_with_es256: TestClient) -> None:
    """Test token generation with ES256."""
    response = client_with_es256.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "es256-client",
            "client_secret": "es256-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    import base64
    import json

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "ES256"


def test_token_es384_algorithm(client_with_es384: TestClient) -> None:
    """Test token generation with ES384."""
    response = client_with_es384.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "es384-client",
            "client_secret": "es384-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    import base64
    import json

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "ES384"


def test_token_es512_algorithm(client_with_es512: TestClient) -> None:
    """Test token generation with ES512."""
    response = client_with_es512.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "es512-client",
            "client_secret": "es512-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    import base64
    import json

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "ES512"


def test_token_eddsa_algorithm(client_with_eddsa: TestClient) -> None:
    """Test token generation with EdDSA."""
    response = client_with_eddsa.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "eddsa-client",
            "client_secret": "eddsa-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    import base64
    import json

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "EdDSA"


@pytest.fixture
def client_with_key_id(temp_db: str) -> TestClient:
    """Create a test client with key ID configured."""
    create_client(
        db_path=temp_db,
        client_id="kid-client",
        secret=b"kid-secret",
        algorithm="RS256",
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
        rsa_private_key=f"@{KEYS_DIR / 'rsa-private.pem'}",
        rsa_key_id="my-rsa-key-1",
    )
    app = create_app(config)
    return TestClient(app)


def test_token_includes_kid_header(client_with_key_id: TestClient) -> None:
    """Test that token includes kid in header when key ID is configured."""
    response = client_with_key_id.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "kid-client",
            "client_secret": "kid-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    import base64
    import json

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "RS256"
    assert header["kid"] == "my-rsa-key-1"


@pytest.fixture
def client_with_issuer(temp_db: str) -> TestClient:
    """Create a test client with APP_URL configured for issuer."""
    create_client(
        db_path=temp_db,
        client_id="issuer-client",
        secret=b"issuer-secret",
        algorithm="HS256",
        signing_secret=b"issuer-signing-secret-1234567890",
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
        app_url="https://auth.example.com",
    )
    app = create_app(config)
    return TestClient(app)


def test_token_includes_issuer_claim(client_with_issuer: TestClient) -> None:
    """Test that token includes iss claim when APP_URL is configured."""
    response = client_with_issuer.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "issuer-client",
            "client_secret": "issuer-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    import base64
    import json

    # Decode payload (second part of JWT)
    payload_b64 = data["access_token"].split(".")[1]
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    assert payload["iss"] == "https://auth.example.com"
    assert payload["sub"] == "issuer-client"
