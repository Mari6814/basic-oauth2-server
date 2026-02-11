"""Tests for crypto utilities."""

import pytest

from basic_oauth2_server.crypto import (
    decrypt,
    decrypt_from_base64,
    encrypt,
    encrypt_to_base64,
)


def test_encrypt_decrypt_roundtrip() -> None:
    """Test that encrypt/decrypt roundtrip works."""
    key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    plaintext = b"hello, world!"

    encrypted = encrypt(plaintext, key)
    decrypted = decrypt(encrypted, key)

    assert decrypted == plaintext


def test_encrypt_decrypt_base64_roundtrip() -> None:
    """Test that base64 encrypt/decrypt roundtrip works."""
    key = b"0123456789abcdef0123456789abcdef"
    plaintext = b"secret data"

    encrypted_b64 = encrypt_to_base64(plaintext, key)
    decrypted = decrypt_from_base64(encrypted_b64, key)

    assert decrypted == plaintext


def test_encrypt_produces_different_output() -> None:
    """Test that encryption produces different output each time (random nonce)."""
    key = b"0123456789abcdef0123456789abcdef"
    plaintext = b"same data"

    encrypted1 = encrypt(plaintext, key)
    encrypted2 = encrypt(plaintext, key)

    assert encrypted1 != encrypted2


def test_decrypt_with_wrong_key_fails() -> None:
    """Test that decryption with wrong key fails."""
    key1 = b"0123456789abcdef0123456789abcdef"
    key2 = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    plaintext = b"secret"

    encrypted = encrypt(plaintext, key1)

    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt(encrypted, key2)


def test_short_key_is_padded() -> None:
    """Test that short keys are padded to 32 bytes."""
    short_key = b"shortkey"
    plaintext = b"test data"

    encrypted = encrypt(plaintext, short_key)
    decrypted = decrypt(encrypted, short_key)

    assert decrypted == plaintext
