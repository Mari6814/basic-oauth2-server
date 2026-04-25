"""Encryption utilities for storing sensitive data."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-GCM.

    Args:
        data: The plaintext data to encrypt.
        key: The encryption key (must be at least 32 bytes; only the first 32 bytes are used).

    Returns:
        The encrypted data with nonce prepended.

    Raises:
        ValueError: If the key is shorter than 32 bytes.
    """
    if len(key) < 32:
        raise ValueError(
            f"Encryption key must be at least 32 bytes, got {len(key)}. "
            "Ensure APP_KEY is set to a sufficiently long secret."
        )
    key = key[:32]

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-GCM.

    Args:
        encrypted_data: The encrypted data with nonce prepended.
        key: The encryption key (must be at least 32 bytes; only the first 32 bytes are used).

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If the key is shorter than 32 bytes or decryption fails.
    """
    if len(key) < 32:
        raise ValueError(
            f"Encryption key must be at least 32 bytes, got {len(key)}. "
            "Ensure APP_KEY is set to a sufficiently long secret."
        )
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
