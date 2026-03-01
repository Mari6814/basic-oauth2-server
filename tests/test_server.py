"""Tests for the OAuth server."""

import os
import base64
import json
from pathlib import Path
from collections.abc import Generator

from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm
import pytest
from fastapi.testclient import TestClient

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import Database, ClientRepository
from basic_oauth2_server.server import create_app


@pytest.fixture
def temp_db(tmp_path: Path) -> Generator[str, None, None]:
    """Create a temporary database for testing using pytest's tmp_path."""
    db_path = tmp_path / "test_oauth.db"

    # Set APP_KEY for encryption
    os.environ["APP_KEY"] = base64.b64encode(b"test-app-key-1234567890").decode()

    db = Database(str(db_path))
    db.create_tables()
    yield str(db_path)


def _create_client(db_path: str, **kwargs) -> None:
    """Test helper: create a client using Database/ClientRepository."""
    db = Database(db_path)
    with db.session() as session:
        ClientRepository(session).create(**kwargs)


@pytest.fixture
def client_with_db(temp_db: str) -> TestClient:
    """Create a test client with a temporary database."""
    # Create a test OAuth client
    _create_client(
        temp_db,
        client_id="test-client",
        client_secret=b"test-secret",
        algorithm=SymmetricAlgorithm.HS256,
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


def b64(s: str) -> str:
    """Transforms any string into its base64 representation decoded as UTF-8."""
    return base64.b64encode(s.encode()).decode()


def test_token_endpoint_success(client_with_db: TestClient) -> None:
    """Test successful token request."""
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": b64("test-secret"),
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
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": b64("test-secret"),
            "scope": "read write",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "read write"


def test_request_subset_of_allowed_scopes(temp_db: str) -> None:
    """A client may request a subset of its configured scopes."""
    # create client with three allowed scopes
    _create_client(
        temp_db,
        client_id="subset-client",
        client_secret=b"subset-secret",
        algorithm=SymmetricAlgorithm.HS256,
        signing_secret=b"subset-signing-secret-000",
        scopes=["read", "write", "admin"],
    )

    config = ServerConfig(host="localhost", port=8080, db_path=temp_db)
    app = create_app(config)
    tc = TestClient(app)

    resp = tc.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "subset-client",
            "client_secret": b64("subset-secret"),
            "scope": "read write",
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data.get("scope") == "read write"


def test_token_endpoint_invalid_scope(client_with_db: TestClient) -> None:
    """Test token request with invalid scope."""
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": b64("test-secret"),
            "scope": "admin",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "invalid_scope"


def test_token_endpoint_invalid_client(client_with_db: TestClient) -> None:
    """Test token request with invalid client."""
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "nonexistent",
            "client_secret": b64("wrong"),
        },
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "invalid_client"


def test_token_endpoint_wrong_secret(client_with_db: TestClient) -> None:
    """Test token request with wrong secret."""
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": b64("wrong-secret"),
        },
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "invalid_client"


def test_token_endpoint_unsupported_grant_type(client_with_db: TestClient) -> None:
    """Test token request with unsupported grant type."""
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "client_secret": b64("test-secret"),
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "unsupported_grant_type"


def test_token_endpoint_with_audience(client_with_db: TestClient) -> None:
    """Test token request with valid audience."""
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": b64("test-secret"),
            "audience": "https://api.test.com",
        },
    )

    assert response.status_code == 200


def test_request_one_of_allowed_audiences(temp_db: str) -> None:
    """A client may request any single audience from its configured list."""
    # create client with two allowed audiences
    _create_client(
        temp_db,
        client_id="audience-client",
        client_secret=b"audience-secret",
        algorithm=SymmetricAlgorithm.HS256,
        signing_secret=b"audience-signing-secret-000",
        audiences=["https://api.a.example", "https://api.b.example"],
    )

    config = ServerConfig(host="localhost", port=8080, db_path=temp_db)
    app = create_app(config)
    tc = TestClient(app)

    resp = tc.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "audience-client",
            "client_secret": b64("audience-secret"),
            "audience": "https://api.b.example",
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data

    payload_b64 = data["access_token"].split(".")[1]
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    assert payload.get("aud") == "https://api.b.example"


def test_token_endpoint_invalid_audience(client_with_db: TestClient) -> None:
    """Test token request with invalid audience."""
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": b64("test-secret"),
            "audience": "https://wrong.com",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "invalid_audience"


def test_token_endpoint_audience_when_none_configured(temp_db: str) -> None:
    """Requesting an audience when the client has none configured should fail."""
    _create_client(
        temp_db,
        client_id="no-aud-client",
        client_secret=b"no-aud-secret",
        algorithm=SymmetricAlgorithm.HS256,
        signing_secret=b"no-aud-signing-secret-00000",
    )

    config = ServerConfig(host="localhost", port=8080, db_path=temp_db)
    app = create_app(config)
    tc = TestClient(app)

    resp = tc.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "no-aud-client",
            "client_secret": b64("no-aud-secret"),
            "audience": "https://any.example.com",
        },
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_audience"


# Test keys directory
KEYS_DIR = Path(__file__).parent / "keys"


@pytest.fixture
def client_with_rsa(temp_db: str) -> TestClient:
    """Create a test client using RS256 algorithm."""
    _create_client(
        temp_db,
        client_id="rsa-client",
        client_secret=b"rsa-secret",
        algorithm=AsymmetricAlgorithm.RS256,
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
    _create_client(
        temp_db,
        client_id="es256-client",
        client_secret=b"es256-secret",
        algorithm=AsymmetricAlgorithm.ES256,
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
    _create_client(
        temp_db,
        client_id="es384-client",
        client_secret=b"es384-secret",
        algorithm=AsymmetricAlgorithm.ES384,
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
    _create_client(
        temp_db,
        client_id="es512-client",
        client_secret=b"es512-secret",
        algorithm=AsymmetricAlgorithm.ES512,
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
    _create_client(
        temp_db,
        client_id="eddsa-client",
        client_secret=b"eddsa-secret",
        algorithm=AsymmetricAlgorithm.EdDSA,
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
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "rsa-client",
            "client_secret": b64("rsa-secret"),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "RS256"


@pytest.fixture
def client_with_ps256(temp_db: str) -> TestClient:
    """Create a test client using PS256 algorithm (RSA-PSS)."""
    _create_client(
        temp_db,
        client_id="ps256-client",
        client_secret=b"ps256-secret",
        algorithm=AsymmetricAlgorithm.PS256,
    )

    config = ServerConfig(
        host="localhost",
        port=8080,
        db_path=temp_db,
        rsa_private_key=f"@{KEYS_DIR / 'rsa-private.pem'}",
    )
    app = create_app(config)
    return TestClient(app)


def test_token_ps256_algorithm(client_with_ps256: TestClient) -> None:
    """Test token generation with PS256 (RSA-PSS)."""
    response = client_with_ps256.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "ps256-client",
            "client_secret": b64("ps256-secret"),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "PS256"


def test_token_es256_algorithm(client_with_es256: TestClient) -> None:
    """Test token generation with ES256."""
    response = client_with_es256.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "es256-client",
            "client_secret": b64("es256-secret"),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "ES256"


def test_token_es384_algorithm(client_with_es384: TestClient) -> None:
    """Test token generation with ES384."""
    response = client_with_es384.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "es384-client",
            "client_secret": b64("es384-secret"),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "ES384"


def test_token_es512_algorithm(client_with_es512: TestClient) -> None:
    """Test token generation with ES512."""
    response = client_with_es512.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "es512-client",
            "client_secret": b64("es512-secret"),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "ES512"


def test_token_eddsa_algorithm(client_with_eddsa: TestClient) -> None:
    """Test token generation with EdDSA."""
    response = client_with_eddsa.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "eddsa-client",
            "client_secret": b64("eddsa-secret"),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "EdDSA"


@pytest.fixture
def client_with_key_id(temp_db: str) -> TestClient:
    """Create a test client with key ID configured."""
    _create_client(
        temp_db,
        client_id="kid-client",
        client_secret=b"kid-secret",
        algorithm=AsymmetricAlgorithm.RS256,
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
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "kid-client",
            "client_secret": b64("kid-secret"),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    header_b64 = data["access_token"].split(".")[0]
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    assert header["alg"] == "RS256"
    assert header["kid"] == "my-rsa-key-1"


@pytest.fixture
def client_with_issuer(temp_db: str) -> TestClient:
    """Create a test client with APP_URL configured for issuer."""
    _create_client(
        temp_db,
        client_id="issuer-client",
        client_secret=b"issuer-secret",
        algorithm=SymmetricAlgorithm.HS256,
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
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "issuer-client",
            "client_secret": b64("issuer-secret"),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    # Decode payload (second part of JWT)
    payload_b64 = data["access_token"].split(".")[1]
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    assert payload["iss"] == "https://auth.example.com"
    assert payload["sub"] == "issuer-client"


def test_token_endpoint_basic_auth(client_with_db: TestClient) -> None:
    """Test successful token request using HTTP Basic auth."""

    credentials = base64.b64encode(
        f"test-client:{b64('test-secret')}".encode()
    ).decode()
    response = client_with_db.post(
        "/oauth2/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": f"Basic {credentials}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"


def test_token_endpoint_basic_auth_invalid_secret(client_with_db: TestClient) -> None:
    """Test Basic auth with wrong secret."""

    credentials = base64.b64encode(
        f"test-client:{b64('wrong-secret')}".encode()
    ).decode()
    response = client_with_db.post(
        "/oauth2/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": f"Basic {credentials}"},
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_token_endpoint_basic_auth_unknown_client(client_with_db: TestClient) -> None:
    """Test Basic auth with unknown client."""

    credentials = base64.b64encode(
        f"unknown-client:{b64('some-secret')}".encode()
    ).decode()
    response = client_with_db.post(
        "/oauth2/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": f"Basic {credentials}"},
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_token_endpoint_basic_auth_priority(client_with_db: TestClient) -> None:
    """Test that Basic auth takes priority over form credentials."""

    # Provide correct credentials in header, wrong in form
    credentials = base64.b64encode(
        f"test-client:{b64('test-secret')}".encode()
    ).decode()
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-client",
            "client_secret": b64("wrong-secret"),
        },
        headers={"Authorization": f"Basic {credentials}"},
    )

    # Should succeed because header takes priority
    assert response.status_code == 200


def test_token_endpoint_missing_credentials(client_with_db: TestClient) -> None:
    """Test error when no credentials provided."""
    response = client_with_db.post(
        "/oauth2/token",
        data={"grant_type": "client_credentials"},
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
