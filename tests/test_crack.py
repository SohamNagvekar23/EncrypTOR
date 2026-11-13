"""Tests for encryptor.crack: known-plaintext recovery of the classic-mode offset."""

from __future__ import annotations

import dataclasses
import itertools

import pytest

from encryptor import (
    CrackStoppedError,
    EncryptorError,
    InputFormatError,
    OffsetNotFoundError,
    classic,
    crack,
    pi_stream,
)

MESSAGE = b"Known plaintext: meet me at the old bridge at nine."
SMALL_BOUND = 4096


@pytest.fixture
def small_bound(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(classic, "OFFSET_BOUND", SMALL_BOUND)
    return SMALL_BOUND


# ---------------------------------------------------------------------------- constants


def test_constants() -> None:
    assert crack.CRACK_PREFIX_BYTES == 4
    assert crack.CRACK_CHUNK_DIGITS == 16384
    assert crack.CRACK_PROGRESS_CHUNK_DIGITS == 12288


# ---------------------------------------------------------------------- recovers offset


@pytest.mark.parametrize("offset", [0, 1, 777, 5000])
def test_recovers_offset(offset: int) -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, offset)
    result = crack.crack(MESSAGE, ciphertext, max_offset=8192)
    assert isinstance(result, crack.CrackResult)
    assert result.offset == offset
    assert result.candidates_tried == offset + 1
    assert isinstance(result.elapsed_seconds, float)
    assert result.elapsed_seconds >= 0
    # The recovered offset really decrypts the message.
    assert classic.decrypt_at_offset(ciphertext, result.offset) == MESSAGE


def test_max_offset_is_positional_or_keyword() -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, 12)
    assert crack.crack(MESSAGE, ciphertext, 64).offset == 12


def test_recovers_last_offset_in_range() -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, 1023)
    result = crack.crack(MESSAGE, ciphertext, max_offset=1024)
    assert result.offset == 1023
    assert result.candidates_tried == 1024


def test_recovers_passphrase_offset_with_default_range(small_bound: int) -> None:
    passphrase = "open sesame"
    ciphertext = classic.encrypt(MESSAGE, passphrase)
    result = crack.crack(MESSAGE, ciphertext)
    assert result.offset == classic.derive_offset(passphrase)
    assert 0 <= result.offset < small_bound
    assert result.candidates_tried == result.offset + 1
    assert classic.decrypt_at_offset(ciphertext, result.offset) == MESSAGE


def test_default_range_is_read_at_call_time(small_bound: int) -> None:
    # Offset 5000 is outside the patched default range [0, 4096).
    ciphertext = classic.encrypt_at_offset(MESSAGE, 5000)
    with pytest.raises(OffsetNotFoundError) as excinfo:
        crack.crack(MESSAGE, ciphertext)
    assert excinfo.value.candidates_tried == small_bound


@pytest.mark.parametrize("chunk_digits", [16, 100, 4096, 16384])
def test_result_does_not_depend_on_chunk_size(
    monkeypatch: pytest.MonkeyPatch, chunk_digits: int
) -> None:
    # Small chunks force prefix hits and full needles to straddle chunk boundaries.
    monkeypatch.setattr(crack, "CRACK_CHUNK_DIGITS", chunk_digits)
    for offset in (0, 15, 16, 99, 100, 313):
        ciphertext = classic.encrypt_at_offset(MESSAGE, offset)
        result = crack.crack(MESSAGE, ciphertext, max_offset=400)
        assert result.offset == offset
        assert result.candidates_tried == offset + 1


def test_odd_offset_between_byte_boundaries() -> None:
    # Offsets count hex digits, so odd offsets (half-byte shifts) must be found too.
    for offset in (3, 255, 2049):
        ciphertext = classic.encrypt_at_offset(MESSAGE, offset)
        assert crack.crack(MESSAGE, ciphertext, max_offset=2100).offset == offset


def test_accepts_bytearray_and_memoryview() -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, 50)
    result = crack.crack(bytearray(MESSAGE), memoryview(ciphertext), max_offset=128)
    assert result.offset == 50


def test_short_message_uses_whole_message_as_prefix() -> None:
    # Shorter than CRACK_PREFIX_BYTES: still works; offset 0 is the first candidate.
    for plaintext in (b"a", b"ab", b"abc"):
        ciphertext = classic.encrypt_at_offset(plaintext, 0)
        result = crack.crack(plaintext, ciphertext, max_offset=64)
        assert result.offset == 0
        assert result.candidates_tried == 1


def test_short_message_result_reproduces_the_ciphertext() -> None:
    # A short message may match an earlier coincidental offset, but whatever is
    # returned must be the first offset that maps the plaintext to the ciphertext.
    plaintext = b"hi"
    ciphertext = classic.encrypt_at_offset(plaintext, 3000)
    result = crack.crack(plaintext, ciphertext, max_offset=3001)
    assert result.offset <= 3000
    assert classic.encrypt_at_offset(plaintext, result.offset) == ciphertext
    # Known plaintext reveals the key bytes: k[i] = p[i] ^ c[i] ^ c[i-1].
    key = bytes(
        [
            plaintext[0] ^ ciphertext[0] ^ classic.CHAIN_IV,
            plaintext[1] ^ ciphertext[1] ^ ciphertext[0],
        ]
    )
    needle = key.hex().upper()
    expected_first = pi_stream.pi_hex_digits(0, 3004).find(needle)
    assert 0 <= expected_first <= 3000
    assert result.offset == expected_first
    assert result.candidates_tried == expected_first + 1


def test_prefix_match_with_wrong_tail_is_not_accepted() -> None:
    # Same first 4 key bytes as offset 0 but a different tail: offset 0 must be rejected
    # by the full comparison, and nothing else in the range matches.
    genuine = classic.encrypt_at_offset(MESSAGE, 0)
    forged = bytearray(genuine)
    forged[-1] ^= 0xFF
    with pytest.raises(OffsetNotFoundError):
        crack.crack(MESSAGE, bytes(forged), max_offset=512)


def test_crack_result_is_frozen_dataclass() -> None:
    result = crack.CrackResult(offset=5, candidates_tried=6, elapsed_seconds=0.25)
    assert dataclasses.is_dataclass(result)
    assert (result.offset, result.candidates_tried, result.elapsed_seconds) == (5, 6, 0.25)
    assert result == crack.CrackResult(5, 6, 0.25)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.offset = 7  # type: ignore[misc]


# ------------------------------------------------------------------------- out of range


def test_offset_out_of_range_reports_failure() -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, 9000)
    with pytest.raises(OffsetNotFoundError) as excinfo:
        crack.crack(MESSAGE, ciphertext, max_offset=4096)
    error = excinfo.value
    assert isinstance(error, EncryptorError)
    assert error.candidates_tried == 4096
    assert isinstance(error.elapsed_seconds, float)
    assert error.elapsed_seconds >= 0


def test_offset_equal_to_max_offset_is_out_of_range() -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, 300)
    with pytest.raises(OffsetNotFoundError) as excinfo:
        crack.crack(MESSAGE, ciphertext, max_offset=300)
    assert excinfo.value.candidates_tried == 300
    assert crack.crack(MESSAGE, ciphertext, max_offset=301).offset == 300


def test_unrelated_ciphertext_is_not_found() -> None:
    ciphertext = bytes(len(MESSAGE))
    with pytest.raises(OffsetNotFoundError) as excinfo:
        crack.crack(MESSAGE, ciphertext, max_offset=1000)
    assert excinfo.value.candidates_tried == 1000


# ----------------------------------------------------------------------------- bad input


@pytest.mark.parametrize(
    ("plaintext", "ciphertext"),
    [
        (b"", b""),
        (b"", b"abc"),
        (b"abc", b""),
        (b"abc", b"abcd"),
        (b"abcd", b"abc"),
    ],
)
def test_empty_or_unequal_inputs_are_rejected(plaintext: bytes, ciphertext: bytes) -> None:
    with pytest.raises(InputFormatError):
        crack.crack(plaintext, ciphertext, max_offset=16)


@pytest.mark.parametrize("max_offset", [0, -1, -4096])
def test_non_positive_max_offset_is_a_value_error(max_offset: int) -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, 0)
    with pytest.raises(ValueError):
        crack.crack(MESSAGE, ciphertext, max_offset=max_offset)


# ------------------------------------------------------------------- progress / stop


class Recorder:
    """A progress callback that records every call and stops after ``stop_after`` calls."""

    def __init__(self, stop_after: int | None = None) -> None:
        self.calls: list[tuple[int, int]] = []
        self.stop_after = stop_after

    def __call__(self, tried: int, total: int) -> bool:
        self.calls.append((tried, total))
        return self.stop_after is None or len(self.calls) < self.stop_after


def test_progress_none_is_the_default_and_gives_the_same_result() -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, 777)
    plain = crack.crack(MESSAGE, ciphertext, 2048)
    explicit = crack.crack(MESSAGE, ciphertext, 2048, progress=None)
    assert (plain.offset, plain.candidates_tried) == (explicit.offset, explicit.candidates_tried)
    assert (plain.offset, plain.candidates_tried) == (777, 778)


def test_progress_is_keyword_only() -> None:
    ciphertext = classic.encrypt_at_offset(MESSAGE, 12)
    with pytest.raises(TypeError):
        crack.crack(MESSAGE, ciphertext, 64, Recorder())  # type: ignore[misc]


def test_progress_reports_monotonic_counts_and_still_finds_the_offset() -> None:
    recorder = Recorder()
    ciphertext = classic.encrypt_at_offset(MESSAGE, 28000)
    result = crack.crack(MESSAGE, ciphertext, 40000, progress=recorder)
    assert (result.offset, result.candidates_tried) == (28000, 28001)
    assert classic.decrypt_at_offset(ciphertext, result.offset) == MESSAGE
    tried = [count for count, _ in recorder.calls]
    # Called before the first chunk and after every chunk scanned without a match.
    assert len(tried) >= 3
    assert tried[0] == 0
    assert all(total == 40000 for _, total in recorder.calls)
    assert all(low <= high for low, high in itertools.pairwise(tried))
    assert all(0 <= count <= result.offset for count in tried)


def test_progress_chunks_are_at_most_the_progress_chunk_size() -> None:
    recorder = Recorder()
    ciphertext = classic.encrypt_at_offset(MESSAGE, 25000)
    with pytest.raises(OffsetNotFoundError) as excinfo:
        crack.crack(MESSAGE, ciphertext, 20000, progress=recorder)
    assert excinfo.value.candidates_tried == 20000
    tried = [count for count, _ in recorder.calls]
    # One report per table chunk, so cancel latency is one progress chunk.
    steps = [high - low for low, high in itertools.pairwise(tried)]
    assert steps
    assert max(steps) <= crack.CRACK_PROGRESS_CHUNK_DIGITS
    assert len(tried) >= 20000 // crack.CRACK_PROGRESS_CHUNK_DIGITS + 1
    assert all(count < 20000 for count in tried)


@pytest.mark.parametrize("stop_after", [1, 2])
def test_progress_returning_false_stops_the_search(stop_after: int) -> None:
    recorder = Recorder(stop_after=stop_after)
    ciphertext = classic.encrypt_at_offset(MESSAGE, 25000)
    with pytest.raises(CrackStoppedError) as excinfo:
        crack.crack(MESSAGE, ciphertext, 30000, progress=recorder)
    error = excinfo.value
    assert isinstance(error, EncryptorError)
    assert not isinstance(error, OffsetNotFoundError)
    assert len(recorder.calls) == stop_after
    assert error.candidates_tried == recorder.calls[-1][0]
    assert isinstance(error.elapsed_seconds, float)
    assert error.elapsed_seconds >= 0


def test_progress_stop_on_the_first_call_does_no_bbp_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_run(position: int, count: int) -> str:
        raise AssertionError("pi digits were generated after the search was stopped")

    monkeypatch.setattr(crack, "pi_hex_digits", must_not_run)
    ciphertext = classic.encrypt_at_offset(MESSAGE, 5)
    with pytest.raises(CrackStoppedError) as excinfo:
        crack.crack(MESSAGE, ciphertext, 64, progress=lambda tried, total: False)
    assert excinfo.value.candidates_tried == 0


@pytest.mark.parametrize("chunk_digits", [16, 100, 4096])
def test_progress_path_result_does_not_depend_on_chunk_size(
    monkeypatch: pytest.MonkeyPatch, chunk_digits: int
) -> None:
    monkeypatch.setattr(crack, "CRACK_PROGRESS_CHUNK_DIGITS", chunk_digits)
    for offset in (0, 15, 16, 99, 100, 313):
        ciphertext = classic.encrypt_at_offset(MESSAGE, offset)
        result = crack.crack(MESSAGE, ciphertext, max_offset=400, progress=Recorder())
        assert (result.offset, result.candidates_tried) == (offset, offset + 1)


def test_progress_stop_is_honoured_while_extending_a_prefix_hit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A long known plaintext: after the prefix hits, the full needle needs many more
    # chunks. A stop request must be seen during that extension, not after it.
    monkeypatch.setattr(crack, "CRACK_PROGRESS_CHUNK_DIGITS", 16)
    generated: list[int] = []
    real_digits = crack.pi_hex_digits

    def counting(position: int, count: int) -> str:
        generated.append(count)
        return real_digits(position, count)

    monkeypatch.setattr(crack, "pi_hex_digits", counting)
    message = bytes(range(32, 127)) * 4  # 380 bytes = 760 hex digits
    ciphertext = classic.encrypt_at_offset(message, 5)
    recorder = Recorder(stop_after=3)
    with pytest.raises(CrackStoppedError) as excinfo:
        crack.crack(message, ciphertext, 64, progress=recorder)
    assert len(recorder.calls) == 3
    assert excinfo.value.candidates_tried == recorder.calls[-1][0]
    assert all(0 <= tried <= 5 for tried, _ in recorder.calls)
    # Stopped after a few chunks, long before the 760-digit needle was generated.
    assert sum(generated) <= 3 * 16
