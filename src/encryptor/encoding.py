"""Hex and decimal text encodings used by the CLI.

Error messages never echo the offending input.
"""

from __future__ import annotations

from encryptor import Buffer, InputFormatError

_DECIMAL_CHARS = "0123456789 \t\n\r\x0b\x0c"


def encode_hex(data: Buffer) -> str:
    """Return ``data`` as lowercase hex without separators.

    Time O(n), space O(n) for the result.
    """
    return data.hex()


def decode_hex(text: str) -> bytes:
    """Parse hex text (any case, surrounding whitespace ignored); ``""`` gives ``b""``.

    Raises ``InputFormatError`` on a non-hex character or an odd number of digits.
    Time O(n), space O(n) for the result plus the stripped copy of the text.
    """
    stripped = text.strip()
    try:
        data = bytes.fromhex(stripped)
    except ValueError:
        raise InputFormatError(
            "invalid hex input: expected an even number of hex digits (0-9, a-f)"
        ) from None
    # bytes.fromhex skips whitespace between bytes; the length check rejects it.
    if 2 * len(data) != len(stripped):
        raise InputFormatError(
            "invalid hex input: expected an even number of hex digits (0-9, a-f)"
        )
    return data


def encode_decimal(data: Buffer) -> str:
    """Return ``data`` as space-separated decimal byte values; ``b""`` gives ``""``.

    Time O(n), space O(n) for the result.
    """
    return " ".join(map(str, data))


def decode_decimal(text: str) -> bytes:
    """Parse whitespace-separated decimal byte values; ``""`` gives ``b""``.

    Every token must consist of ASCII digits only and have a value in 0..255, so
    signs, underscores, prefixes, fractions and non-ASCII digits are all rejected.
    Raises ``InputFormatError`` otherwise. Time O(n), space O(n) for the token list
    and the result.
    """
    # After stripping every allowed character from both ends, anything left over
    # contains a character that is neither an ASCII digit nor ASCII whitespace.
    if not text.isascii() or text.strip(_DECIMAL_CHARS):
        raise InputFormatError(
            "invalid decimal input: expected space-separated byte values from 0 to 255"
        )
    try:
        return bytes(map(int, text.split()))
    except ValueError:
        raise InputFormatError(
            "invalid decimal input: expected space-separated byte values from 0 to 255"
        ) from None
