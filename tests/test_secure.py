"""Tests for encryptor.secure: ChaCha20-Poly1305 with a scrypt-derived key.

An autouse fixture lowers ``secure.SCRYPT_N`` so the suite stays fast. It only changes a
parameter handed to the library's scrypt; one test restores the production value.
"""

from __future__ import annotations

import pytest

from encryptor import (
    AuthenticationError,
    EncryptorError,
    MalformedCiphertextError,
    TruncatedCiphertextError,
    UnsupportedVersionError,
    secure,
)

# The production cost, captured before the autouse fixture patches it.
PRODUCTION_SCRYPT_N = secure.SCRYPT_N
FAST_SCRYPT_N = 1 << 10

HEADER_LEN = 29
OVERHEAD = 45
SALT = slice(1, 17)
NONCE = slice(17, 29)

PASSPHRASE = "correct horse battery staple"

ROUND_TRIP_INPUTS: list[bytes] = [
    b"",
    b"a",
    b"hello, world",
    "\U0001f512\U0001f680\U0001f600".encode(),
    "naïve café 日本語 жщэ π \U0001f512".encode(),
    bytes(range(256)),
    ("The quick brown fox jumps over the lazy dog. " * 120).encode(),
    bytes((i * 131 + 7) % 256 for i in range(100 * 1024)),
]


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secure, "SCRYPT_N", FAST_SCRYPT_N)


# ---------------------------------------------------------------------------- constants


def test_production_constants_and_real_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    assert PRODUCTION_SCRYPT_N == 1 << 17
    assert secure.SCRYPT_R == 8
    assert secure.SCRYPT_P == 1
    assert secure.KEY_LEN == 32

    monkeypatch.setattr(secure, "SCRYPT_N", PRODUCTION_SCRYPT_N)
    blob = secure.encrypt(b"production parameters", PASSPHRASE)
    assert secure.decrypt(blob, PASSPHRASE) == b"production parameters"


def test_format_constants() -> None:
    assert secure.VERSION == 1
    assert secure.SALT_LEN == 16
    assert secure.NONCE_LEN == 12
    assert secure.TAG_LEN == 16
    assert secure.HEADER_LEN == HEADER_LEN
    assert secure.MIN_BLOB_LEN == OVERHEAD


def test_scrypt_cost_is_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    # A blob made with one cost must not open with another: proves the patched
    # constant really reaches the KDF.
    blob = secure.encrypt(b"cost matters", PASSPHRASE)
    monkeypatch.setattr(secure, "SCRYPT_N", FAST_SCRYPT_N * 2)
    with pytest.raises(AuthenticationError):
        secure.decrypt(blob, PASSPHRASE)
    monkeypatch.setattr(secure, "SCRYPT_N", FAST_SCRYPT_N)
    assert secure.decrypt(blob, PASSPHRASE) == b"cost matters"


# --------------------------------------------------------------------------- round trip


@pytest.mark.parametrize("plaintext", ROUND_TRIP_INPUTS, ids=lambda data: f"{len(data)}-bytes")
def test_round_trip(plaintext: bytes) -> None:
    blob = secure.encrypt(plaintext, PASSPHRASE)
    assert isinstance(blob, bytes)
    assert len(blob) == len(plaintext) + OVERHEAD
    assert blob[0] == 1
    recovered = secure.decrypt(blob, PASSPHRASE)
    assert isinstance(recovered, bytes)
    assert recovered == plaintext


def test_ciphertext_does_not_contain_plaintext() -> None:
    plaintext = b"this exact sentence must not be visible in the blob"
    blob = secure.encrypt(plaintext, PASSPHRASE)
    assert plaintext not in blob
    assert plaintext[:12] not in blob


def test_accepts_bytearray_and_memoryview() -> None:
    plaintext = b"buffer protocol"
    assert secure.decrypt(secure.encrypt(bytearray(plaintext), PASSPHRASE), PASSPHRASE) == plaintext
    assert (
        secure.decrypt(secure.encrypt(memoryview(plaintext), PASSPHRASE), PASSPHRASE) == plaintext
    )
    blob = secure.encrypt(plaintext, PASSPHRASE)
    assert secure.decrypt(bytearray(blob), PASSPHRASE) == plaintext
    assert secure.decrypt(memoryview(blob), PASSPHRASE) == plaintext


def test_non_ascii_passphrase() -> None:
    passphrase = "pässwörd \U0001f511 日本"
    blob = secure.encrypt(b"unicode passphrase", passphrase)
    assert secure.decrypt(blob, passphrase) == b"unicode passphrase"
    with pytest.raises(AuthenticationError):
        secure.decrypt(blob, "passwrd")


# ------------------------------------------------------------------ random salt and nonce


def test_two_encryptions_differ() -> None:
    plaintext = b"same input twice"
    first = secure.encrypt(plaintext, PASSPHRASE)
    second = secure.encrypt(plaintext, PASSPHRASE)
    assert first != second
    assert first[SALT] != second[SALT]
    assert first[NONCE] != second[NONCE]
    assert first[HEADER_LEN:] != second[HEADER_LEN:]
    assert secure.decrypt(first, PASSPHRASE) == plaintext
    assert secure.decrypt(second, PASSPHRASE) == plaintext


def test_salts_and_nonces_are_unique_over_many_runs() -> None:
    blobs = [secure.encrypt(b"", PASSPHRASE) for _ in range(20)]
    assert len({blob[SALT] for blob in blobs}) == 20
    assert len({blob[NONCE] for blob in blobs}) == 20


# ----------------------------------------------------------------------- wrong passphrase


@pytest.mark.parametrize(
    "wrong",
    ["", "wrong", PASSPHRASE + " ", PASSPHRASE.upper(), PASSPHRASE[:-1]],
)
def test_wrong_passphrase_raises_authentication_error(wrong: str) -> None:
    blob = secure.encrypt(b"top secret", PASSPHRASE)
    with pytest.raises(AuthenticationError):
        secure.decrypt(blob, wrong)


def test_authentication_error_message_reveals_nothing() -> None:
    plaintext = b"top secret payload"
    blob = secure.encrypt(plaintext, PASSPHRASE)
    with pytest.raises(AuthenticationError) as excinfo:
        secure.decrypt(blob, "wrong-guess-123")
    message = str(excinfo.value)
    assert "authentication failed" in message
    assert "wrong-guess-123" not in message
    assert PASSPHRASE not in message
    assert plaintext.decode() not in message
    # Raised "from None": the library's InvalidTag is not chained into the report.
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__ is True


# ------------------------------------------------------------------------------- tamper


def test_every_single_bit_flip_is_rejected() -> None:
    plaintext = b"abc"
    blob = secure.encrypt(plaintext, PASSPHRASE)
    assert len(blob) == 48
    for bit in range(len(blob) * 8):
        tampered = bytearray(blob)
        tampered[bit // 8] ^= 1 << (bit % 8)
        expected: type[EncryptorError] = UnsupportedVersionError if bit < 8 else AuthenticationError
        with pytest.raises(EncryptorError) as excinfo:
            secure.decrypt(bytes(tampered), PASSPHRASE)
        assert type(excinfo.value) is expected, f"bit {bit}"
    # The untouched blob still opens.
    assert secure.decrypt(blob, PASSPHRASE) == plaintext


def test_truncated_or_extended_ciphertext_is_rejected() -> None:
    blob = secure.encrypt(b"some longer plaintext", PASSPHRASE)
    with pytest.raises(AuthenticationError):
        secure.decrypt(blob[:-1], PASSPHRASE)
    with pytest.raises(AuthenticationError):
        secure.decrypt(blob + b"\x00", PASSPHRASE)
    with pytest.raises(AuthenticationError):
        secure.decrypt(blob[:HEADER_LEN] + blob[HEADER_LEN + 1 :], PASSPHRASE)


def test_swapped_header_is_rejected() -> None:
    # The header (version, salt, nonce) is authenticated as associated data.
    first = secure.encrypt(b"message one", PASSPHRASE)
    second = secure.encrypt(b"message two", PASSPHRASE)
    with pytest.raises(AuthenticationError):
        secure.decrypt(second[:HEADER_LEN] + first[HEADER_LEN:], PASSPHRASE)


# ---------------------------------------------------------------------------- structure


def test_empty_blob_is_truncated() -> None:
    with pytest.raises(TruncatedCiphertextError):
        secure.decrypt(b"", PASSPHRASE)


@pytest.mark.parametrize("length", [1, 2, 28, 29, 30, 44])
def test_short_blob_with_valid_version_is_truncated(length: int) -> None:
    blob = secure.encrypt(b"", PASSPHRASE)
    assert len(blob) == OVERHEAD
    with pytest.raises(TruncatedCiphertextError):
        secure.decrypt(blob[:length], PASSPHRASE)
    with pytest.raises(TruncatedCiphertextError):
        secure.decrypt(b"\x01" + bytes(length - 1), PASSPHRASE)


@pytest.mark.parametrize("version", [0, 2, 3, 0x81, 0xFF])
def test_unknown_version_is_rejected(version: int) -> None:
    blob = bytearray(secure.encrypt(b"versioned", PASSPHRASE))
    blob[0] = version
    with pytest.raises(UnsupportedVersionError):
        secure.decrypt(bytes(blob), PASSPHRASE)


def test_version_is_checked_before_length() -> None:
    with pytest.raises(UnsupportedVersionError):
        secure.decrypt(b"\x02", PASSPHRASE)
    with pytest.raises(UnsupportedVersionError):
        secure.decrypt(b"\x02" + bytes(43), PASSPHRASE)


def test_minimum_length_blob_of_zeros_fails_authentication() -> None:
    with pytest.raises(AuthenticationError):
        secure.decrypt(b"\x01" + bytes(44), PASSPHRASE)


def test_exception_hierarchy() -> None:
    assert issubclass(MalformedCiphertextError, EncryptorError)
    assert issubclass(TruncatedCiphertextError, MalformedCiphertextError)
    assert issubclass(UnsupportedVersionError, MalformedCiphertextError)
    assert issubclass(AuthenticationError, EncryptorError)
    assert not issubclass(AuthenticationError, MalformedCiphertextError)
    assert not issubclass(MalformedCiphertextError, AuthenticationError)


# ------------------------------------------------------------- scrypt memory failure


class OutOfMemoryScrypt:
    """Stands in for the library's ``Scrypt`` when its work area cannot be allocated."""

    def __init__(self, *, salt: bytes, length: int, n: int, r: int, p: int) -> None:
        self.arguments = (salt, length, n, r, p)

    def derive(self, key_material: bytes) -> bytes:
        raise MemoryError("boom")


def assert_memory_error_report(error: EncryptorError) -> None:
    assert "memory" in str(error).lower()
    assert "boom" not in str(error)
    # Raised "from None": the MemoryError is not chained into the report.
    assert error.__cause__ is None
    assert error.__suppress_context__ is True
    # Not misreported as a wrong passphrase or a malformed blob (CLI exit code 1).
    assert not isinstance(error, AuthenticationError | MalformedCiphertextError)


def test_scrypt_memory_error_on_encrypt_is_an_encryptor_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(secure, "Scrypt", OutOfMemoryScrypt)
    with pytest.raises(EncryptorError) as excinfo:
        secure.encrypt(b"x", "p")
    assert_memory_error_report(excinfo.value)


def test_scrypt_memory_error_on_decrypt_is_an_encryptor_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob = secure.encrypt(b"x", "p")
    monkeypatch.setattr(secure, "Scrypt", OutOfMemoryScrypt)
    for candidate in (blob, b"\x01" + bytes(44)):
        with pytest.raises(EncryptorError) as excinfo:
            secure.decrypt(candidate, "p")
        assert_memory_error_report(excinfo.value)


def test_scrypt_is_a_module_level_name_looked_up_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The memory-error tests patch ``secure.Scrypt``; this shows that patch point is the one in use.
    seen: list[tuple[bytes, int, int, int, int]] = []

    class RecordingScrypt:
        def __init__(self, *, salt: bytes, length: int, n: int, r: int, p: int) -> None:
            seen.append((salt, length, n, r, p))

        def derive(self, key_material: bytes) -> bytes:
            return bytes(32)

    monkeypatch.setattr(secure, "Scrypt", RecordingScrypt)
    blob = secure.encrypt(b"x", "p")
    assert seen == [(blob[SALT], 32, FAST_SCRYPT_N, 8, 1)]
