"""Utility functions."""

import base64
from pathlib import Path


def decode_prefixed_utf8(value: str, allow_from_file: bool = False) -> bytes:
    """
    Parse a value from various encodings into bytes.

    Args:
        value: The utf-8 string to decode into bytes. Supported formats:
            - ``@path/to/file``: Read contents from file. The file is expected to contain bytes. Its content will not be decoded.
            - ``base64:<base64 string>``: Standard base64 encoded value. Padding is optional.
            - ``base64url:<base64url string>``: URL-safe base64 encoded value. Padding is optional. May silently ignore non-URL-safe characters.
            - ``hex:<hex string>`` or ``0x<hex string>``: Hexadecimal encoded value
            - else: Treated as plain text and encoded as UTF-8 bytes
        allow_from_file: Whether to allow reading from files.

    Returns:
        Decoded bytes from the input string.

    Raises:
        FileNotFoundError: If @ prefix is used but file doesn't exist.
        ValueError: If base64 or hex decoding fails, or if file reading is not allowed.
    """
    if value.startswith("@"):
        if not allow_from_file:
            raise ValueError(
                "Reading from file has been disabled. To enable, set allow_from_file=True"
            )
        # Remove the @ prefix and read the file
        file_path = Path(value[1:])
        if not file_path.is_file():
            raise FileNotFoundError(f"Secret file not found: {file_path}")
        return file_path.read_bytes()

    if value.startswith("base64:"):
        encoded = value[7:]
        if not encoded:
            raise ValueError("Invalid base64 encoding: empty value")
        padding_needed = (4 - len(encoded) % 4) % 4
        encoded_padded = encoded + ("=" * padding_needed)
        try:
            return base64.b64decode(encoded_padded, validate=True)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}") from e

    if value.startswith("base64url:"):
        encoded = value[10:]
        if not encoded:
            raise ValueError("Invalid base64url encoding: empty value")
        padding_needed = (4 - len(encoded) % 4) % 4
        encoded_padded = encoded + ("=" * padding_needed)
        try:
            return base64.urlsafe_b64decode(encoded_padded)
        except Exception as e:
            raise ValueError(f"Invalid base64url encoding: {e}") from e

    if (is_hex := value.startswith("hex:")) or value.startswith("0x"):
        hex_value = value[4:] if is_hex else value[2:]
        if not hex_value:
            raise ValueError("Invalid hex encoding: empty value")
        try:
            return bytes.fromhex(hex_value)
        except Exception as e:
            raise ValueError(f"Invalid hex encoding: {e}") from e

    # Plain text
    return value.encode("utf-8")
