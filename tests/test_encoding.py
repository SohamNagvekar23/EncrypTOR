"""Tests for encryptor.encoding: hex and decimal text helpers used by the CLI."""

from __future__ import annotations

import pytest

from encryptor import EncryptorError, InputFormatError, encoding

ALL_BYTES = bytes(range(256))


# --------------------------------------------------------------------------------- hex


def test_encode_hex_is_lowercase_without_separators() -> None:
    assert encoding.encode_hex(b"\x00\x0a\xff\xab") == "000affab"
    assert encoding.encode_hex(b"") == ""


@pytest.mark.parametrize("data", [b"", b"\x00", b"hello", ALL_BYTES, ALL_BYTES * 4])
def test_hex_round_trip(data: bytes) -> None:
    text = encoding.encode_hex(data)
    assert isinstance(text, str)
    assert len(text) == 2 * len(data)
    assert text == text.lower()
    decoded = encoding.decode_hex(text)
    assert isinstance(decoded, bytes)
    assert decoded == data


def test_encode_hex_accepts_any_buffer() -> None:
    assert encoding.encode_hex(bytearray(b"\x01\x02")) == "0102"
    assert encoding.encode_hex(memoryview(b"\x01\x02")) == "0102"


def test_decode_hex_accepts_uppercase_and_mixed_case() -> None:
    assert encoding.decode_hex("DEADBEEF") == b"\xde\xad\xbe\xef"
    assert encoding.decode_hex("DeAdbEeF") == b"\xde\xad\xbe\xef"
    assert encoding.decode_hex(encoding.encode_hex(ALL_BYTES).upper()) == ALL_BYTES


def test_decode_hex_strips_surrounding_whitespace() -> None:
    assert encoding.decode_hex("  0aff\n") == b"\x0a\xff"
    assert encoding.decode_hex("0aff\r\n") == b"\x0a\xff"
    assert encoding.decode_hex("") == b""
    assert encoding.decode_hex(" \n") == b""


@pytest.mark.parametrize("text", ["zz", "abc", "0", "0x10", "12 3", "gg00", "12,34"])
def test_decode_hex_rejects_bad_input(text: str) -> None:
    with pytest.raises(InputFormatError):
        encoding.decode_hex(text)


def test_decode_hex_error_does_not_echo_input() -> None:
    with pytest.raises(InputFormatError) as excinfo:
        encoding.decode_hex("zzqqzzqq")
    assert "zzqq" not in str(excinfo.value)
    assert str(excinfo.value) != ""


# ----------------------------------------------------------------------------- decimal


def test_encode_decimal_format() -> None:
    assert encoding.encode_decimal(b"Hi\x00") == "72 105 0"
    assert encoding.encode_decimal(b"\xff") == "255"
    assert encoding.encode_decimal(b"") == ""


@pytest.mark.parametrize("data", [b"", b"\x00", b"hello", ALL_BYTES, ALL_BYTES * 4])
def test_decimal_round_trip(data: bytes) -> None:
    text = encoding.encode_decimal(data)
    assert isinstance(text, str)
    assert text == " ".join(str(value) for value in data)
    decoded = encoding.decode_decimal(text)
    assert isinstance(decoded, bytes)
    assert decoded == data


def test_encode_decimal_accepts_any_buffer() -> None:
    assert encoding.encode_decimal(bytearray(b"\x01\xff")) == "1 255"
    assert encoding.encode_decimal(memoryview(b"\x01\xff")) == "1 255"


def test_decode_decimal_splits_on_any_whitespace() -> None:
    assert encoding.decode_decimal("72 105 0") == b"Hi\x00"
    assert encoding.decode_decimal("  72\t105\n0  \n") == b"Hi\x00"
    assert encoding.decode_decimal("") == b""
    assert encoding.decode_decimal("  \n ") == b""
    assert encoding.decode_decimal("0 255") == b"\x00\xff"


@pytest.mark.parametrize(
    "text",
    ["256", "-1", "1,2", "1_0", "+5", "0x10", "1.0", "ff", "12 300", "1 two 3", "٣"],
)
def test_decode_decimal_rejects_bad_input(text: str) -> None:
    with pytest.raises(InputFormatError):
        encoding.decode_decimal(text)


def test_decode_decimal_error_does_not_echo_input() -> None:
    with pytest.raises(InputFormatError) as excinfo:
        encoding.decode_decimal("1 2 98765 4")
    assert "98765" not in str(excinfo.value)
    assert str(excinfo.value) != ""


def test_input_format_error_is_an_encryptor_error() -> None:
    assert issubclass(InputFormatError, EncryptorError)
    assert issubclass(EncryptorError, Exception)
