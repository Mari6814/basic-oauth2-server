"""Tests for the consent_token module."""

import base64
import json
import time

import pytest
from pytest import MonkeyPatch

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.consent_token import (
    CONSENT_TOKEN_EXPIRES_IN,
    ConsentClaims,
    create_consent_token,
    verify_consent_token,
)
from basic_oauth2_server.exceptions import InvalidRequestException
from jws_algorithms import SymmetricAlgorithm


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(autouse=True)
def set_app_key(monkeypatch: MonkeyPatch) -> None:
    """Set APP_KEY env var for all tests in this module."""
    monkeypatch.setenv(
        "APP_KEY", base64.b64encode(b"test-consent-key-32bytes!!!!!!!!").decode()
    )


@pytest.fixture
def config() -> ServerConfig:
    """Default server config (no app_url) used for consent token tests."""
    return ServerConfig()


@pytest.fixture
def valid_token(config: ServerConfig) -> str:
    """A freshly signed, valid consent token with minimal required fields."""
    return create_consent_token(
        username="alice",
        client_id="myclient",
        redirect_uri="https://example.com/cb",
        code_challenge="abc123",
        code_challenge_method="S256",
        state="xyz",
        config=config,
    )


@pytest.fixture
def token_with_scope(config: ServerConfig) -> str:
    """A valid consent token that includes a scope claim."""
    return create_consent_token(
        username="alice",
        client_id="myclient",
        redirect_uri="https://example.com/cb",
        code_challenge="abc123",
        code_challenge_method="S256",
        state="xyz",
        scope="read write",
        config=config,
    )


@pytest.fixture
def token_with_audience(config: ServerConfig) -> str:
    """A valid consent token that includes an audience claim."""
    return create_consent_token(
        username="alice",
        client_id="myclient",
        redirect_uri="https://example.com/cb",
        code_challenge="abc123",
        code_challenge_method="S256",
        state="xyz",
        audience="https://api.example.com",
        config=config,
    )


@pytest.fixture
def expired_token(config: ServerConfig) -> str:
    """A consent token whose expiry is already in the past."""
    return create_consent_token(
        username="alice",
        client_id="myclient",
        redirect_uri="https://example.com/cb",
        code_challenge="abc123",
        code_challenge_method="S256",
        state="xyz",
        expires_in=-1,
        config=config,
    )


class TestTokenStructure:
    def test_is_three_part_jwt(self, valid_token: str) -> None:
        assert len(valid_token.split(".")) == 3

    def test_header_uses_hs512(self, valid_token: str) -> None:
        header = json.loads(_b64url_decode(valid_token.split(".")[0]))
        assert header["alg"] == "HS512"
        assert header["typ"] == "JWT"

    def test_payload_contains_required_claims(self, valid_token: str) -> None:
        payload = json.loads(_b64url_decode(valid_token.split(".")[1]))
        assert payload["sub"] == "alice"
        assert payload["client_id"] == "myclient"
        assert payload["redirect_uri"] == "https://example.com/cb"
        assert payload["code_challenge"] == "abc123"
        assert payload["code_challenge_method"] == "S256"
        assert payload["state"] == "xyz"
        assert "iat" in payload
        assert "exp" in payload

    def test_expiry_within_lifetime(self, valid_token: str) -> None:
        before = int(time.time()) - 1
        payload = json.loads(_b64url_decode(valid_token.split(".")[1]))
        assert payload["exp"] >= before + CONSENT_TOKEN_EXPIRES_IN

    def test_scope_included_when_provided(self, token_with_scope: str) -> None:
        payload = json.loads(_b64url_decode(token_with_scope.split(".")[1]))
        assert payload["scope"] == "read write"

    def test_scope_absent_when_not_provided(self, valid_token: str) -> None:
        payload = json.loads(_b64url_decode(valid_token.split(".")[1]))
        assert "scope" not in payload

    def test_audience_included_when_provided(self, token_with_audience: str) -> None:
        payload = json.loads(_b64url_decode(token_with_audience.split(".")[1]))
        assert payload["audience"] == "https://api.example.com"

    def test_audience_absent_when_not_provided(self, valid_token: str) -> None:
        payload = json.loads(_b64url_decode(valid_token.split(".")[1]))
        assert "audience" not in payload


class TestVerifyRoundTrip:
    def test_returns_consent_claims_dataclass(
        self, valid_token: str, config: ServerConfig
    ) -> None:
        claims = verify_consent_token(valid_token, config=config)
        assert isinstance(claims, ConsentClaims)

    def test_required_fields(self, valid_token: str, config: ServerConfig) -> None:
        claims = verify_consent_token(valid_token, config=config)
        assert claims.username == "alice"
        assert claims.client_id == "myclient"
        assert claims.redirect_uri == "https://example.com/cb"
        assert claims.code_challenge == "abc123"
        assert claims.code_challenge_method == "S256"
        assert claims.state == "xyz"
        assert claims.scope is None
        assert claims.audience is None

    def test_with_scope(self, token_with_scope: str, config: ServerConfig) -> None:
        claims = verify_consent_token(token_with_scope, config=config)
        assert claims.scope == "read write"
        assert claims.audience is None

    def test_with_audience(
        self, token_with_audience: str, config: ServerConfig
    ) -> None:
        claims = verify_consent_token(token_with_audience, config=config)
        assert claims.audience == "https://api.example.com"
        assert claims.scope is None


class TestVerifyRejectsExpiry:
    def test_expired_token(self, expired_token: str, config: ServerConfig) -> None:
        with pytest.raises(InvalidRequestException, match="expired"):
            verify_consent_token(expired_token, config=config)


class TestVerifyRejectsSignature:
    def test_tampered_payload(self, valid_token: str, config: ServerConfig) -> None:
        header_b64, payload_b64, sig_b64 = valid_token.split(".")
        payload = json.loads(_b64url_decode(payload_b64))
        payload["sub"] = "eve"
        tampered_payload_b64 = _b64url_encode(json.dumps(payload).encode())
        tampered_token = f"{header_b64}.{tampered_payload_b64}.{sig_b64}"
        with pytest.raises(InvalidRequestException, match="signature"):
            verify_consent_token(tampered_token, config=config)

    def test_tampered_header(self, valid_token: str, config: ServerConfig) -> None:
        header_b64, payload_b64, sig_b64 = valid_token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        header["alg"] = "none"
        tampered_header_b64 = _b64url_encode(json.dumps(header).encode())
        tampered_token = f"{tampered_header_b64}.{payload_b64}.{sig_b64}"
        with pytest.raises(InvalidRequestException, match="algorithm"):
            verify_consent_token(tampered_token, config=config)

    def test_wrong_signature(self, valid_token: str, config: ServerConfig) -> None:
        header_b64, payload_b64, _ = valid_token.split(".")
        fake_sig = _b64url_encode(b"totallyfakesignature")
        with pytest.raises(InvalidRequestException, match="signature"):
            verify_consent_token(
                f"{header_b64}.{payload_b64}.{fake_sig}", config=config
            )

    def test_zero_byte_signature(self, valid_token: str, config: ServerConfig) -> None:
        header_b64, payload_b64, _ = valid_token.split(".")
        empty_sig = _b64url_encode(b"")
        with pytest.raises(InvalidRequestException, match="signature"):
            verify_consent_token(
                f"{header_b64}.{payload_b64}.{empty_sig}", config=config
            )

    def test_wrong_key(
        self, valid_token: str, config: ServerConfig, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "APP_KEY", base64.b64encode(b"different-key-32-bytes!!!!!!!!!!").decode()
        )
        with pytest.raises(InvalidRequestException, match="signature"):
            verify_consent_token(valid_token, config=config)


class TestVerifyRejectsMalformed:
    def test_random_string(self, config: ServerConfig) -> None:
        with pytest.raises(InvalidRequestException):
            verify_consent_token("not.a.jwt", config=config)

    def test_too_few_parts(self, config: ServerConfig) -> None:
        with pytest.raises(InvalidRequestException):
            verify_consent_token("not.jwt", config=config)

    def test_too_many_parts(self, config: ServerConfig) -> None:
        with pytest.raises(InvalidRequestException):
            verify_consent_token("a.b.c.d", config=config)

    def test_empty_string(self, config: ServerConfig) -> None:
        with pytest.raises(InvalidRequestException):
            verify_consent_token("", config=config)

    def test_invalid_base64_in_payload(self, config: ServerConfig) -> None:
        header_b64 = _b64url_encode(b'{"alg":"HS512","typ":"JWT"}')
        with pytest.raises(InvalidRequestException):
            verify_consent_token(f"{header_b64}.!!!invalid!!!.fakesig", config=config)

    def test_non_json_payload(self, config: ServerConfig) -> None:
        header_b64 = _b64url_encode(b'{"alg":"HS512","typ":"JWT"}')
        bad_payload = _b64url_encode(b"not json at all")
        fake_sig = _b64url_encode(b"sig")
        with pytest.raises(InvalidRequestException):
            verify_consent_token(
                f"{header_b64}.{bad_payload}.{fake_sig}", config=config
            )

    def test_truncated_token(self, valid_token: str, config: ServerConfig) -> None:
        with pytest.raises(InvalidRequestException):
            verify_consent_token(valid_token[:-10], config=config)


def _make_signed_token(claims: dict, app_key: bytes) -> str:
    """Create a properly signed HS512 JWT with custom claims (for testing edge cases)."""

    _alg = SymmetricAlgorithm.HS512
    header_b64 = _b64url_encode(b'{"alg":"HS512","typ":"JWT"}')

    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    sig = _alg.sign(app_key, f"{header_b64}.{payload_b64}".encode())
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


class TestVerifyRejectsInvalidClaims:
    """Test that verify_consent_token rejects tokens with bad iss/aud/iat claims."""

    @pytest.fixture
    def app_key_bytes(self) -> bytes:
        return base64.b64decode(base64.b64encode(b"test-consent-key-32bytes!!!!!!!!"))

    def test_wrong_issuer(self, config: ServerConfig, app_key_bytes: bytes) -> None:
        now = int(time.time())
        claims = {
            "sub": "alice",
            "client_id": "c",
            "redirect_uri": "u",
            "code_challenge": "x",
            "code_challenge_method": "S256",
            "state": "s",
            "iss": "https://wrong-issuer.example.com",
            "aud": config.app_url,
            "iat": now,
            "exp": now + 300,
        }
        token = _make_signed_token(claims, app_key_bytes)
        with pytest.raises(InvalidRequestException, match="issuer"):
            verify_consent_token(token, config=config)

    def test_wrong_audience(self, config: ServerConfig, app_key_bytes: bytes) -> None:
        now = int(time.time())
        claims = {
            "sub": "alice",
            "client_id": "c",
            "redirect_uri": "u",
            "code_challenge": "x",
            "code_challenge_method": "S256",
            "state": "s",
            "iss": config.app_url,
            "aud": "https://wrong-audience.example.com",
            "iat": now,
            "exp": now + 300,
        }
        token = _make_signed_token(claims, app_key_bytes)
        with pytest.raises(InvalidRequestException, match="audience"):
            verify_consent_token(token, config=config)

    def test_future_iat(self, config: ServerConfig, app_key_bytes: bytes) -> None:
        now = int(time.time())
        claims = {
            "sub": "alice",
            "client_id": "c",
            "redirect_uri": "u",
            "code_challenge": "x",
            "code_challenge_method": "S256",
            "state": "s",
            "iss": config.app_url,
            "aud": config.app_url,
            "iat": now + 9999,
            "exp": now + 300,
        }
        token = _make_signed_token(claims, app_key_bytes)
        with pytest.raises(InvalidRequestException, match="future"):
            verify_consent_token(token, config=config)

    def test_missing_required_claim(
        self, config: ServerConfig, app_key_bytes: bytes
    ) -> None:
        now = int(time.time())
        # Missing "sub"
        claims = {
            "client_id": "c",
            "redirect_uri": "u",
            "code_challenge": "x",
            "code_challenge_method": "S256",
            "state": "s",
            "iss": config.app_url,
            "aud": config.app_url,
            "iat": now,
            "exp": now + 300,
        }
        token = _make_signed_token(claims, app_key_bytes)
        with pytest.raises(InvalidRequestException, match="missing claim"):
            verify_consent_token(token, config=config)
