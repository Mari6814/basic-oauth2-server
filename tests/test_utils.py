"""Tests for decode_prefixed_utf8 utility (bytes parsing from various encodings)."""

from pathlib import Path
import base64

import pytest

from basic_oauth2_server.utils import decode_prefixed_utf8


def test_decode_plain_text() -> None:
    """Test parsing plain text input."""
    result = decode_prefixed_utf8("my-secret")
    assert result == b"my-secret"


def test_decode_base64() -> None:
    """Test parsing base64-encoded input."""
    # "hello" in base64
    result = decode_prefixed_utf8("base64:aGVsbG8=")
    assert result == b"hello"


def test_decode_base64_and_base64url_equivalence() -> None:
    """Test comparing that base64 encoded and base64url encoded values are parsed to the same result"""
    deadbeef = bytes.fromhex("deadbeef")
    b64 = base64.b64encode(deadbeef).decode("ascii")
    b64url = base64.urlsafe_b64encode(deadbeef).decode("ascii")
    # With padding
    assert b64.endswith("=") and b64url.endswith("=")
    assert decode_prefixed_utf8(f"base64:{b64}") == deadbeef
    assert decode_prefixed_utf8(f"base64url:{b64url}") == deadbeef
    # Without padding
    b64_nopad = b64.rstrip("=")
    b64url_nopad = b64url.rstrip("=")
    assert not b64_nopad.endswith("=") and not b64url_nopad.endswith("=")
    assert decode_prefixed_utf8(f"base64:{b64_nopad}") == deadbeef
    assert decode_prefixed_utf8(f"base64url:{b64url_nopad}") == deadbeef


def test_decode_file(tmp_path: Path) -> None:
    """Test parsing bytes from files."""
    file_path = tmp_path / "secret.txt"
    file_path.write_text("file-secret")
    result = decode_prefixed_utf8(f"@{file_path}")
    assert result == b"file-secret"


def test_decode_file_binary(tmp_path: Path) -> None:
    """Test parsing binary bytes from files."""
    binary_data = b"\x00\xffbinary-\x00-secret\xff\x00"
    file_path = tmp_path / "secret.bin"
    file_path.write_bytes(binary_data)
    result = decode_prefixed_utf8(f"@{file_path}")
    assert result == binary_data


def test_decode_invalid_base64() -> None:
    """Test that invalid base64 raises an error."""
    with pytest.raises(ValueError, match="Invalid base64"):
        decode_prefixed_utf8("base64:not-valid-base64!!!")


def test_decode_invalid_hex() -> None:
    """Test that invalid hex raises an error."""
    with pytest.raises(ValueError, match="Invalid hex"):
        decode_prefixed_utf8("0xnotvalidhex")


def test_decode_file_not_found() -> None:
    """Test that missing file raises an error."""
    with pytest.raises(FileNotFoundError):
        decode_prefixed_utf8("@/nonexistent/path/to/secret.txt")


def test_reject_file_when_not_allowed() -> None:
    """Test that file input is rejected when allow_from_file is False."""
    with pytest.raises(ValueError, match="Reading from file has been disabled"):
        decode_prefixed_utf8("@somefile.txt", allow_from_file=False)


def test_decode_empty_hex() -> None:
    """Test that empty hex value raises an error."""
    with pytest.raises(ValueError, match="Invalid hex encoding"):
        decode_prefixed_utf8("0x")


def test_decode_empty_base64() -> None:
    """Test that empty base64 value raises an error."""
    with pytest.raises(ValueError, match="Invalid base64 encoding"):
        decode_prefixed_utf8("base64:")


def test_decode_hex_prefix() -> None:
    """Test that hex: prefix is accepted for hex-encoded input."""
    result = decode_prefixed_utf8("hex:deadbeef")
    assert result == bytes.fromhex("deadbeef")


def test_decode_hex_prefix_invalid() -> None:
    """Test that invalid hex with hex: prefix raises an error."""
    with pytest.raises(ValueError, match="Invalid hex encoding"):
        decode_prefixed_utf8("hex:notvalidhex")
