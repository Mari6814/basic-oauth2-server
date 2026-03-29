"""Tests for the OAuth server."""

import hashlib
import os
import base64
import json
import secrets
import pytest
from pathlib import Path
from collections.abc import Generator
from urllib.parse import urlparse, parse_qs

from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm
from fastapi.testclient import TestClient

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import create_client, init_db
from basic_oauth2_server.server import create_app


@pytest.fixture
def temp_db(tmp_path: Path) -> Generator[str, None, None]:
    """Create a temporary database for testing using pytest's tmp_path."""
    db_path = tmp_path / "test_oauth.db"

    # Set APP_KEY for encryption
    os.environ["APP_KEY"] = base64.b64encode(b"test-app-key-1234567890").decode()

    init_db(str(db_path))
    yield str(db_path)


@pytest.fixture
def client_with_db(temp_db: str) -> TestClient:
    """Create a test client with a temporary database."""
    # Create a test OAuth client
    create_client(
        db_path=temp_db,
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
    create_client(
        db_path=temp_db,
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
            "grant_type": "password",
            "client_id": "test-client",
            "client_secret": b64("test-secret"),
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "invalid_grant"


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
    create_client(
        db_path=temp_db,
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


# Test keys directory
KEYS_DIR = Path(__file__).parent / "keys"


@pytest.fixture
def client_with_rsa(temp_db: str) -> TestClient:
    """Create a test client using RS256 algorithm."""
    create_client(
        db_path=temp_db,
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
    create_client(
        db_path=temp_db,
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
    create_client(
        db_path=temp_db,
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
    create_client(
        db_path=temp_db,
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
    create_client(
        db_path=temp_db,
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
    create_client(
        db_path=temp_db,
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
    create_client(
        db_path=temp_db,
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
    create_client(
        db_path=temp_db,
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

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def _pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and S256 code_challenge."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _basic_auth_header(username: str, password: str) -> dict[str, str]:
    """Build an HTTP Basic Auth header."""
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def test_authorization_code_full_flow(client_with_db: TestClient) -> None:
    """Test complete authorization code flow:

    This test implements the full flow of an OAuth 2.0 Authorization Code grant with PKCE:
        1. authorize: The user is redirected to the /authorize endpoint with PKCE from what ever app they are using. The server responds with a consent object containing the requested scopes and a confirm URL.
        2. consent: After they authorize they have to press the consent link that will redirect them to the confirm URL. The server generates an authorization code and redirects to the client's redirect_uri with the code and state.
        3. confirm: The client receives the authorization code and makes a POST request to /oauth2/token with the code and PKCE verifier to exchange it for an access token.
        4. token exchange: The server validates the authorization code and PKCE verifier, then issues an access token.
    """
    verifier, challenge = _pkce_pair()
    auth_headers = _basic_auth_header("testuser", "testpass")

    # Step 1/2. redirected to /authorize
    response = client_with_db.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "read write",
            "audience": "https://api.test.com",
            "state": "test-state-123",
        },
        headers=auth_headers,
    )
    assert response.status_code == 200
    consent = response.json()
    assert consent["type"] == "consent"
    assert consent["client_id"] == "test-client"
    assert consent["user"] == "testuser"
    assert consent["requested_scopes"] == ["read", "write"]
    assert "confirm_url" in consent

    # Step 3. the previous step would show a consent page to the user, and when they click "Authorize" it would redirect to the confirm URL. We simulate that by directly calling the confirm endpoint with the same parameters and auth.
    response = client_with_db.get(
        "/authorize/confirm",
        params={
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "read write",
            "audience": "https://api.test.com",
            "state": "test-state-123",
        },
        headers=auth_headers,
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = response.headers["location"]
    parsed = urlparse(location)
    query = parse_qs(parsed.query)
    assert "code" in query
    assert query["state"] == ["test-state-123"]
    code = query["code"][0]

    # Step 4. the client receives the code and makes a POST request to /oauth2/token with the code and PKCE verifier to exchange it for an access token.
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "code": code,
            "redirect_uri": "http://localhost/callback",
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "Bearer"
    assert token_data["expires_in"] == 3600
    assert token_data["scope"] == "read write"

    # Validate that the access token is a valid JWT with correct claims
    access_token = token_data["access_token"]
    header_b64, payload_b64, signature_b64 = access_token.split(".")
    header_b64 += "=" * (4 - len(header_b64) % 4)
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    assert header["alg"] == "HS256"
    assert payload["sub"] == "testuser"
    assert payload["aud"] == "https://api.test.com"
    assert set(payload["scope"].split()) == {"read", "write"}


def test_authorization_code_reuse_rejected(client_with_db: TestClient) -> None:
    """Test that an authorization code cannot be used twice."""
    verifier, challenge = _pkce_pair()
    auth_headers = _basic_auth_header("testuser", "testpass")

    # Get auth code
    response = client_with_db.get(
        "/authorize/confirm",
        params={
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "reuse-state",
        },
        headers=auth_headers,
        follow_redirects=False,
    )
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "code": code,
            "redirect_uri": "http://localhost/callback",
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200

    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "code": code,
            "redirect_uri": "http://localhost/callback",
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_authorization_code_wrong_verifier(client_with_db: TestClient) -> None:
    """Test that a wrong PKCE code_verifier is rejected."""
    verifier, challenge = _pkce_pair()
    auth_headers = _basic_auth_header("testuser", "testpass")

    # Get auth code
    response = client_with_db.get(
        "/authorize/confirm",
        params={
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "wrong-verifier-state",
        },
        headers=auth_headers,
        follow_redirects=False,
    )
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    # Exchange with wrong verifier
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "code": code,
            "redirect_uri": "http://localhost/callback",
            "code_verifier": "wrong-verifier-value",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_authorization_code_missing_verifier(client_with_db: TestClient) -> None:
    """Test that missing code_verifier is rejected."""
    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "code": "some-code",
            "redirect_uri": "http://localhost/callback",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_authorize_requires_auth(client_with_db: TestClient) -> None:
    """Test that /authorize returns 401 without Basic Auth."""
    response = client_with_db.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": "test",
            "code_challenge_method": "S256",
            "state": "test-state",
        },
    )
    assert response.status_code == 401


def test_authorize_invalid_client(client_with_db: TestClient) -> None:
    """Test that /authorize rejects unknown client_id."""
    auth_headers = _basic_auth_header("testuser", "testpass")
    response = client_with_db.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "nonexistent",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": "test",
            "code_challenge_method": "S256",
            "state": "test-state",
        },
        headers=auth_headers,
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_authorize_invalid_scope(client_with_db: TestClient) -> None:
    """Test that /authorize rejects invalid scopes."""
    auth_headers = _basic_auth_header("testuser", "testpass")
    response = client_with_db.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": "test",
            "code_challenge_method": "S256",
            "scope": "admin",
            "state": "test-state",
        },
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


def _pkce_s512_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and S512 code_challenge."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha512(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def test_authorization_code_flow_s512_pkce(client_with_db: TestClient) -> None:
    """Test authorization code flow with S512 PKCE method."""
    verifier, challenge = _pkce_s512_pair()
    auth_headers = _basic_auth_header("testuser", "testpass")

    response = client_with_db.get(
        "/authorize/confirm",
        params={
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S512",
            "scope": "read",
            "state": "s512-state",
        },
        headers=auth_headers,
        follow_redirects=False,
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "code": code,
            "redirect_uri": "http://localhost/callback",
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_authorization_code_flow_s512_wrong_verifier(
    client_with_db: TestClient,
) -> None:
    """Test that wrong PKCE verifier is rejected with S512 method."""
    verifier, challenge = _pkce_s512_pair()
    auth_headers = _basic_auth_header("testuser", "testpass")

    response = client_with_db.get(
        "/authorize/confirm",
        params={
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S512",
            "state": "s512-wrong-state",
        },
        headers=auth_headers,
        follow_redirects=False,
    )
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    response = client_with_db.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "code": code,
            "redirect_uri": "http://localhost/callback",
            "code_verifier": "wrong-verifier",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_authorize_redirect_uri_validation(temp_db: str) -> None:
    """Test that redirect_uri must match registered URIs when configured."""
    create_client(
        db_path=temp_db,
        client_id="redirect-client",
        client_secret=b"redirect-secret",
        algorithm=SymmetricAlgorithm.HS256,
        signing_secret=b"redirect-signing-secret-12345",
        redirect_uris=["https://example.com/callback", "https://app.example.com/oauth"],
    )

    config = ServerConfig(host="localhost", port=8080, db_path=temp_db)
    app = create_app(config)
    tc = TestClient(app)
    auth_headers = _basic_auth_header("testuser", "testpass")

    # Test with allowed redirect_uri
    response = tc.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "redirect-client",
            "redirect_uri": "https://example.com/callback",
            "code_challenge": "test-challenge",
            "code_challenge_method": "S256",
            "state": "test-state",
        },
        headers=auth_headers,
    )
    assert response.status_code == 200

    # Test with disallowed redirect_uri
    response = tc.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "redirect-client",
            "redirect_uri": "https://evil.com/callback",
            "code_challenge": "test-challenge",
            "code_challenge_method": "S256",
            "state": "test-state",
        },
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_authorize_redirect_uri_no_restriction(temp_db: str) -> None:
    """Test that empty redirect_uris rejects all redirect URIs."""
    create_client(
        db_path=temp_db,
        client_id="open-client",
        client_secret=b"open-secret",
        algorithm=SymmetricAlgorithm.HS256,
        signing_secret=b"open-signing-secret-123456",
    )

    config = ServerConfig(host="localhost", port=8080, db_path=temp_db)
    app = create_app(config)
    tc = TestClient(app)
    auth_headers = _basic_auth_header("testuser", "testpass")

    response = tc.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "open-client",
            "redirect_uri": "https://any.example.com/callback",
            "code_challenge": "test-challenge",
            "code_challenge_method": "S256",
            "state": "test-state",
        },
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_token_expires_in_configurable(temp_db: str) -> None:
    """Test that token expiry can be configured via ServerConfig."""
    create_client(
        db_path=temp_db,
        client_id="expiry-client",
        client_secret=b"expiry-secret",
        algorithm=SymmetricAlgorithm.HS256,
        signing_secret=b"expiry-signing-secret-12345",
    )

    config = ServerConfig(
        host="localhost", port=8080, db_path=temp_db, token_expires_in=7200
    )
    app = create_app(config)
    tc = TestClient(app)

    response = tc.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "expiry-client",
            "client_secret": b64("expiry-secret"),
        },
    )
    assert response.status_code == 200
    assert response.json()["expires_in"] == 7200
