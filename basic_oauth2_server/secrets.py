"""Utility for loading secrets from various formats.

Supports multiple formats for specifying secrets:
- @path/to/file - Read from file
- base64:... - Base64 encoded
- 0x... - Hex encoded
- hex:... - Hex encoded with hex: prefix
- (plain text) - Raw string

This allows flexibility and clarity when using the CLI or ENV variables to configure
the signing secret and client secrets.
"""

import base64
from pathlib import Path


def parse_secret(value: str, allow_from_file: bool = True) -> bytes:
    """Parse a secret value from various formats.

    Args:
        value: The secret value in one of the supported formats:
            - @path/to/file - Read contents from file
            - base64:... - Base64 encoded value
            - hex:... or 0x... - Hexadecimal encoded value
            - (anything else) - Plain text
        allow_from_file: Whether to allow reading secrets from files (default: True).

    Returns:
        The decoded secret as bytes.

    Raises:
        FileNotFoundError: If @ prefix is used but file doesn't exist.
        ValueError: If base64 or hex decoding fails, or if file reading is not allowed.
    """
    if value.startswith("@"):
        if not allow_from_file:
            raise ValueError(
                "Reading secrets from files is not allowed in this context"
            )
        # File path
        file_path = Path(value[1:])
        if not file_path.is_file():
            raise FileNotFoundError(f"Secret file not found: {file_path}")
        return file_path.read_bytes().strip()

    if value.startswith("base64:"):
        # Base64 encoded
        encoded = value[7:]
        if not encoded:
            raise ValueError("Invalid base64 encoding: empty value")
        try:
            return base64.b64decode(encoded)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}") from e

    if value.startswith("hex:"):
        # Hex encoded with hex: prefix
        hex_value = value[4:]
        if not hex_value:
            raise ValueError("Invalid hex encoding: empty value")
        try:
            return bytes.fromhex(hex_value)
        except Exception as e:
            raise ValueError(f"Invalid hex encoding: {e}") from e

    if value.startswith("0x"):
        # Hex encoded
        hex_value = value[2:]
        if not hex_value:
            raise ValueError("Invalid hex encoding: empty value")
        try:
            return bytes.fromhex(hex_value)
        except Exception as e:
            raise ValueError(f"Invalid hex encoding: {e}") from e

    # Plain text
    return value.encode("utf-8")
