"""Tests for secret parsing utilities."""

import tempfile
from pathlib import Path

import pytest

from basic_oauth2_server.secrets import parse_secret


def test_parse_secret_plain_text() -> None:
    """Test parsing plain text secrets."""
    result = parse_secret("my-secret")
    assert result == b"my-secret"


def test_parse_secret_base64() -> None:
    """Test parsing base64-encoded secrets."""
    # "hello" in base64
    result = parse_secret("base64:aGVsbG8=")
    assert result == b"hello"


def test_parse_secret_hex() -> None:
    """Test parsing hex-encoded secrets."""
    # "hello" in hex
    result = parse_secret("0x68656c6c6f")
    assert result == b"hello"


def test_parse_secret_file() -> None:
    """Test parsing secrets from files."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("file-secret")
        f.flush()
        result = parse_secret(f"@{f.name}")
        assert result == b"file-secret"
        Path(f.name).unlink()


def test_parse_secret_invalid_base64() -> None:
    """Test that invalid base64 raises an error."""
    with pytest.raises(ValueError, match="Invalid base64"):
        parse_secret("base64:not-valid-base64!!!")


def test_parse_secret_invalid_hex() -> None:
    """Test that invalid hex raises an error."""
    with pytest.raises(ValueError, match="Invalid hex"):
        parse_secret("0xnotvalidhex")


def test_parse_secret_file_not_found() -> None:
    """Test that missing file raises an error."""
    with pytest.raises(FileNotFoundError):
        parse_secret("@/nonexistent/path/to/secret.txt")
