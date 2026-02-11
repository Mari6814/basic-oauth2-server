"""Encryption utilities for storing sensitive data."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-GCM.

    Args:
        data: The plaintext data to encrypt.
        key: The encryption key (must be 16, 24, or 32 bytes).

    Returns:
        The encrypted data with nonce prepended.
    """
    # Ensure key is proper length (use first 32 bytes or pad)
    if len(key) < 32:
        key = key.ljust(32, b"\0")
    else:
        key = key[:32]

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-GCM.

    Args:
        encrypted_data: The encrypted data with nonce prepended.
        key: The encryption key.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If decryption fails.
    """
    # Ensure key is proper length
    if len(key) < 32:
        key = key.ljust(32, b"\0")
    else:
        key = key[:32]

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e


def encrypt_to_base64(data: bytes, key: bytes) -> str:
    """Encrypt data and return as base64 string."""
    return base64.b64encode(encrypt(data, key)).decode("ascii")


def decrypt_from_base64(encrypted_b64: str, key: bytes) -> bytes:
    """Decrypt base64-encoded encrypted data."""
    return decrypt(base64.b64decode(encrypted_b64), key)
