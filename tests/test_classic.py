"""Tests for encryptor.classic: the educational (NOT secure) chained pi running-key cipher.

Expected ciphertexts are built from the spec recurrence ``c[i] = p[i] ^ k[i] ^ c[i-1]``
written out here, with key bytes taken from the golden pi digits where possible.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from itertools import islice

import pytest

from encryptor import classic, pi_stream

GOLDEN = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"

# The production bound, captured before any test patches it.
PRODUCTION_OFFSET_BOUND = classic.OFFSET_BOUND
SMALL_BOUND = 4096

ROUND_TRIP_INPUTS: list[bytes] = [
    b"",
    b"a",
    b"hello, world",
    "\U0001f512\U0001f680\U0001f600".encode(),
    "naïve café 日本語 жщэ π \U0001f512".encode(),
    bytes(range(256)),
]


def reference_encrypt(plaintext: bytes, key: bytes, iv: int) -> bytes:
    """The spec recurrence, one byte at a time: c[i] = p[i] ^ k[i] ^ c[i-1]."""
    out = bytearray()
    previous = iv
    for p, k in zip(plaintext, key, strict=True):
        previous = p ^ k ^ previous
        out.append(previous)
    return bytes(out)


def golden_key(offset: int, length: int) -> bytes:
    """Key bytes at a hex-digit offset, read straight from the golden vector."""
    digits = GOLDEN[offset : offset + 2 * length]
    assert len(digits) == 2 * length
    return bytes.fromhex(digits)


def has_short_period(data: bytes) -> bool:
    """True if ``data`` repeats with any period up to half its length."""
    return any(data[period:] == data[:-period] for period in range(1, len(data) // 2 + 1))


@pytest.fixture
def small_bound(monkeypatch: pytest.MonkeyPatch) -> int:
    """Shrink the offset range so passphrase-level tests stay fast."""
    monkeypatch.setattr(classic, "OFFSET_BOUND", SMALL_BOUND)
    return SMALL_BOUND


# ------------------------------------------------------------------ constants and offset


def test_production_constants() -> None:
    assert PRODUCTION_OFFSET_BOUND == 1 << 17
    assert classic.OFFSET_BOUND == 1 << 17
    assert classic.CHAIN_IV == 0xA5


@pytest.mark.parametrize(
    ("passphrase", "expected"),
    [("", 47189), ("password", 82648), ("correct horse", 87601)],
)
def test_derive_offset_reference_values(passphrase: str, expected: int) -> None:
    # Reference values re-derived with hashlib by the test author.
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    assert int.from_bytes(digest, "big") % (1 << 17) == expected
    assert classic.derive_offset(passphrase) == expected


@pytest.mark.parametrize("passphrase", ["x", "pässwörd \U0001f511", "a" * 1000])
def test_derive_offset_is_sha256_mod_bound(passphrase: str) -> None:
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    offset = classic.derive_offset(passphrase)
    assert offset == int.from_bytes(digest, "big") % PRODUCTION_OFFSET_BOUND
    assert 0 <= offset < PRODUCTION_OFFSET_BOUND


def test_derive_offset_reads_bound_at_call_time(small_bound: int) -> None:
    assert classic.derive_offset("") == 2133
    assert classic.derive_offset("password") == 728
    assert classic.derive_offset("a") == 2235
    assert classic.derive_offset("b") == 157
    for word in ("alpha", "beta", "gamma"):
        assert 0 <= classic.derive_offset(word) < small_bound


# --------------------------------------------------------------------------- round trip


@pytest.mark.parametrize("plaintext", ROUND_TRIP_INPUTS)
def test_round_trip_with_passphrase(small_bound: int, plaintext: bytes) -> None:
    ciphertext = classic.encrypt(plaintext, "round trip passphrase")
    assert isinstance(ciphertext, bytes)
    assert len(ciphertext) == len(plaintext)
    recovered = classic.decrypt(ciphertext, "round trip passphrase")
    assert isinstance(recovered, bytes)
    assert recovered == plaintext


@pytest.mark.parametrize("offset", [0, 1, 2, 63, 1000, 4095])
@pytest.mark.parametrize("plaintext", ROUND_TRIP_INPUTS)
def test_round_trip_at_offset(plaintext: bytes, offset: int) -> None:
    ciphertext = classic.encrypt_at_offset(plaintext, offset)
    assert len(ciphertext) == len(plaintext)
    assert classic.decrypt_at_offset(ciphertext, offset) == plaintext


def test_round_trip_long_text() -> None:
    plaintext = ("The quick brown fox jumps over the lazy dog. " * 120)[:5000].encode()
    assert len(plaintext) == 5000
    ciphertext = classic.encrypt_at_offset(plaintext, 1000)
    assert len(ciphertext) == 5000
    assert ciphertext != plaintext
    assert classic.decrypt_at_offset(ciphertext, 1000) == plaintext


def test_empty_input_gives_empty_output(small_bound: int) -> None:
    assert classic.encrypt(b"", "pw") == b""
    assert classic.decrypt(b"", "pw") == b""
    assert classic.encrypt_at_offset(b"", 0) == b""
    assert classic.decrypt_at_offset(b"", 0) == b""


def test_passphrase_functions_use_derived_offset(small_bound: int) -> None:
    plaintext = b"offset wiring check"
    offset = classic.derive_offset("wiring")
    ciphertext = classic.encrypt(plaintext, "wiring")
    assert ciphertext == classic.encrypt_at_offset(plaintext, offset)
    assert classic.decrypt(ciphertext, "wiring") == classic.decrypt_at_offset(ciphertext, offset)


def test_default_bound_round_trip() -> None:
    # One round trip with the production bound ("password" derives offset 82648).
    plaintext = b"production bound"
    ciphertext = classic.encrypt(plaintext, "password")
    assert ciphertext == classic.encrypt_at_offset(plaintext, 82648)
    assert classic.decrypt(ciphertext, "password") == plaintext


def test_accepts_bytearray_and_memoryview() -> None:
    plaintext = b"buffer protocol"
    expected = classic.encrypt_at_offset(plaintext, 5)
    assert classic.encrypt_at_offset(bytearray(plaintext), 5) == expected
    assert classic.encrypt_at_offset(memoryview(plaintext), 5) == expected
    assert classic.decrypt_at_offset(bytearray(expected), 5) == plaintext
    assert classic.decrypt_at_offset(memoryview(expected), 5) == plaintext


def test_input_is_not_modified() -> None:
    data = bytearray(b"do not touch")
    classic.encrypt_at_offset(data, 3)
    classic.decrypt_at_offset(data, 3)
    assert data == bytearray(b"do not touch")


# ----------------------------------------------------------------------------- chaining


@pytest.mark.parametrize("offset", [0, 1, 2, 17, 32])
def test_matches_spec_recurrence_with_golden_key(offset: int) -> None:
    plaintext = b"aaaaaaa"
    key = golden_key(offset, len(plaintext))
    expected = reference_encrypt(plaintext, key, 0xA5)
    assert classic.encrypt_at_offset(plaintext, offset) == expected
    assert classic.decrypt_at_offset(expected, offset) == plaintext


def test_first_byte_uses_chain_iv() -> None:
    ciphertext = classic.encrypt_at_offset(b"a", 0)
    assert ciphertext == bytes([ord("a") ^ 0x24 ^ 0xA5])


def test_repeated_characters_do_not_repeat_in_ciphertext(small_bound: int) -> None:
    plaintext = b"aaaaaaa"
    offset = classic.derive_offset("chain")
    key = bytes(islice(pi_stream.keystream(offset), len(plaintext)))
    ciphertext = classic.encrypt(plaintext, "chain")

    unchained = bytes(p ^ k for p, k in zip(plaintext, key, strict=True))
    assert ciphertext != unchained
    assert ciphertext[0] == plaintext[0] ^ key[0] ^ classic.CHAIN_IV
    assert ciphertext == reference_encrypt(plaintext, key, classic.CHAIN_IV)

    assert len(set(ciphertext)) > 1
    assert not has_short_period(ciphertext)


def test_repeated_characters_at_offset_zero_golden() -> None:
    plaintext = b"aaaaaaa"
    ciphertext = classic.encrypt_at_offset(plaintext, 0)
    assert ciphertext == reference_encrypt(plaintext, golden_key(0, 7), 0xA5)
    assert len(set(ciphertext)) > 1
    assert not has_short_period(ciphertext)


def test_sixty_four_repeated_bytes() -> None:
    plaintext = b"\x00" * 64
    offset = 250
    key = bytes(islice(pi_stream.keystream(offset), 64))
    ciphertext = classic.encrypt_at_offset(plaintext, offset)
    assert ciphertext == reference_encrypt(plaintext, key, classic.CHAIN_IV)
    assert ciphertext != bytes(p ^ k for p, k in zip(plaintext, key, strict=True))
    assert len(set(ciphertext)) > 16
    assert not has_short_period(ciphertext)


def test_chain_iv_is_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(classic, "CHAIN_IV", 0x00)
    plaintext = b"aaaaaaa"
    expected = reference_encrypt(plaintext, golden_key(0, 7), 0x00)
    assert classic.encrypt_at_offset(plaintext, 0) == expected
    assert classic.decrypt_at_offset(expected, 0) == plaintext


def test_plaintext_change_propagates_through_chain() -> None:
    # Follows from the recurrence: XOR-ing delta into p[j] XORs delta into every c[i], i >= j.
    plaintext = bytearray(b"the chain carries every earlier byte forward")
    position, delta = 10, 0x41
    base = classic.encrypt_at_offset(plaintext, 40)
    plaintext[position] ^= delta
    changed = classic.encrypt_at_offset(plaintext, 40)
    assert changed[:position] == base[:position]
    assert changed[position:] == bytes(value ^ delta for value in base[position:])


def test_ciphertext_bit_flip_affects_two_plaintext_bytes() -> None:
    # p[i] = c[i] ^ k[i] ^ c[i-1]: c[j] feeds p[j] and p[j+1] only.
    plaintext = b"no integrity protection here"
    ciphertext = bytearray(classic.encrypt_at_offset(plaintext, 9))
    ciphertext[5] ^= 0x01
    recovered = classic.decrypt_at_offset(ciphertext, 9)
    expected = bytearray(plaintext)
    expected[5] ^= 0x01
    expected[6] ^= 0x01
    assert recovered == bytes(expected)


# ----------------------------------------------------------------------- wrong passphrase


def test_wrong_passphrase_gives_different_output(small_bound: int) -> None:
    plaintext = b"attack at dawn, bring snacks"
    assert classic.derive_offset("a") != classic.derive_offset("b")
    ciphertext = classic.encrypt(plaintext, "a")
    assert classic.encrypt(plaintext, "b") != ciphertext
    wrong = classic.decrypt(ciphertext, "b")
    assert isinstance(wrong, bytes)
    assert len(wrong) == len(plaintext)
    assert wrong != plaintext
    assert classic.decrypt(ciphertext, "a") == plaintext


def test_different_offsets_give_different_ciphertext() -> None:
    plaintext = b"same message, different offsets"
    outputs = {classic.encrypt_at_offset(plaintext, offset) for offset in range(12)}
    assert len(outputs) == 12


# ---------------------------------------------------------------------------- streaming


def split(data: bytes, sizes: list[int]) -> list[bytes]:
    """Cut ``data`` into consecutive pieces of the given sizes; the rest is the last piece."""
    parts: list[bytes] = []
    start = 0
    for size in sizes:
        parts.append(data[start : start + size])
        start += size
    parts.append(data[start:])
    return parts


STREAM_MESSAGE = bytes((i * 37 + 11) % 256 for i in range(700))

SPLITS: list[list[bytes]] = [
    [STREAM_MESSAGE],
    split(STREAM_MESSAGE, [1, 2, 3, 250, 6, 256]),
    split(STREAM_MESSAGE, [0, 0, 255, 0, 1, 0, 257, 0]),
    split(STREAM_MESSAGE, [256, 256]),
    [STREAM_MESSAGE[i : i + 1] for i in range(len(STREAM_MESSAGE))],
    [b"", STREAM_MESSAGE, b""],
]


@pytest.mark.parametrize("offset", [0, 301])
@pytest.mark.parametrize("parts", SPLITS, ids=lambda parts: f"{len(parts)}-parts")
def test_chunked_equals_one_shot(parts: list[bytes], offset: int) -> None:
    assert b"".join(parts) == STREAM_MESSAGE
    expected = classic.encrypt_at_offset(STREAM_MESSAGE, offset)

    encrypted = b"".join(classic.encrypt_chunks(parts, offset))
    assert encrypted == expected

    cipher_parts = [expected[i : i + 97] for i in range(0, len(expected), 97)]
    assert b"".join(classic.decrypt_chunks(cipher_parts, offset)) == STREAM_MESSAGE

    same_split = split(expected, [len(part) for part in parts[:-1]])
    assert b"".join(classic.decrypt_chunks(same_split, offset)) == STREAM_MESSAGE


def test_chunks_accept_lazy_iterables_and_buffers() -> None:
    def produce() -> Iterator[bytearray | memoryview]:
        yield bytearray(STREAM_MESSAGE[:10])
        yield memoryview(STREAM_MESSAGE)[10:300]
        yield bytearray()
        yield memoryview(STREAM_MESSAGE)[300:]

    expected = classic.encrypt_at_offset(STREAM_MESSAGE, 12)
    pieces = list(classic.encrypt_chunks(produce(), 12))
    assert all(isinstance(piece, bytes) for piece in pieces)
    assert b"".join(pieces) == expected


def test_chunks_of_nothing_give_nothing() -> None:
    assert b"".join(classic.encrypt_chunks([], 0)) == b""
    assert b"".join(classic.encrypt_chunks([b"", b""], 0)) == b""
    assert b"".join(classic.decrypt_chunks([], 0)) == b""


def test_chunk_boundary_at_keystream_block_edge(monkeypatch: pytest.MonkeyPatch) -> None:
    # Narrow keystream blocks (4 bytes) so chunk edges fall before, on and after block edges.
    monkeypatch.setattr(pi_stream, "KEYSTREAM_BLOCK_DIGITS", 8)
    plaintext = bytes(range(32))
    expected = reference_encrypt(plaintext, golden_key(0, 32), 0xA5)
    assert classic.encrypt_at_offset(plaintext, 0) == expected
    for sizes in ([3, 1, 4, 5], [4, 4, 4], [7, 9], [1] * 31):
        parts = split(plaintext, sizes)
        assert b"".join(classic.encrypt_chunks(parts, 0)) == expected
        assert b"".join(classic.decrypt_chunks(split(expected, sizes), 0)) == plaintext


# ---------------------------------------------------------------------- argument errors


def test_negative_offset_is_rejected() -> None:
    with pytest.raises(ValueError):
        classic.encrypt_at_offset(b"abc", -1)
    with pytest.raises(ValueError):
        classic.decrypt_at_offset(b"abc", -1)
    with pytest.raises(ValueError):
        list(classic.encrypt_chunks([b"abc"], -1))
    with pytest.raises(ValueError):
        list(classic.decrypt_chunks([b"abc"], -1))
