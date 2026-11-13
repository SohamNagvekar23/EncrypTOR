"""Tests for encryptor.pi_stream: BBP hex digits of pi and the batched keystream.

Expected values come from two sources that share nothing with the BBP code under test:
the 64-digit golden vector from the spec, and a slow Machin-formula reference written
in this file (integer fixed point, no floats).
"""

from __future__ import annotations

from itertools import islice

import pytest

from encryptor import EncryptorError, PrecisionError, pi_stream

# First 64 hex digits of pi after the point (from the spec).
GOLDEN = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"

# Number of digits the Machin reference fixture produces.
REFERENCE_DIGITS = 2**14 + 64

# 16-digit windows at far positions. Every literal was reproduced by the Machin
# reference below (run out to 131,087 digits, which is too slow to repeat per test run).
FAR_LITERALS: dict[int, str] = {
    1000: "49F1C09B075372C9",
    4096: "5A04ABFC800BCADC",
    9999: "68AC8FCFB8016CBD",
    16384: "CEA31A15FC3F4432",
    20000: "E937C2354A69FF66",
    32768: "9E8149929AD99C72",
    65536: "30043414C9267212",
    131071: "1587F6278F004BC5",
}


def _atan_inverse(x: int, one: int) -> int:
    """Return floor-ish ``atan(1/x) * one`` by the alternating Taylor series."""
    power = one // x
    total = power
    x_squared = x * x
    divisor = 1
    sign = -1
    while power:
        power //= x_squared
        divisor += 2
        total += sign * (power // divisor)
        sign = -sign
    return total


def machin_pi_hex(count: int, guard_bits: int = 64) -> str:
    """First ``count`` hex digits of pi after the point, by Machin's formula.

    pi = 16*atan(1/5) - 4*atan(1/239), evaluated with ``4*count + guard_bits``
    fractional bits. Independent of BBP: no modular exponentiation, no digit extraction.
    """
    bits = 4 * count + guard_bits
    one = 1 << bits
    pi_fixed = 16 * _atan_inverse(5, one) - 4 * _atan_inverse(239, one)
    fraction = pi_fixed - 3 * one
    return format(fraction >> guard_bits, f"0{count}X")


def key_bytes_from_digits(digits: str, offset: int, length: int) -> bytes:
    """Key bytes per the spec: two hex digits per byte, high nibble first."""
    return bytes(
        16 * int(digits[offset + 2 * i], 16) + int(digits[offset + 2 * i + 1], 16)
        for i in range(length)
    )


@pytest.fixture(scope="module")
def reference() -> str:
    """The first ``REFERENCE_DIGITS`` hex digits of pi from the Machin reference."""
    return machin_pi_hex(REFERENCE_DIGITS)


# --------------------------------------------------------------------------- reference


def test_reference_matches_golden(reference: str) -> None:
    assert len(reference) == REFERENCE_DIGITS
    assert reference[:64] == GOLDEN


def test_reference_is_stable_across_precision(reference: str) -> None:
    # A shorter, differently rounded run must agree on its whole length.
    assert machin_pi_hex(300, guard_bits=96) == reference[:300]


def test_far_literals_agree_with_reference(reference: str) -> None:
    checked = 0
    for position, literal in FAR_LITERALS.items():
        if position + 16 <= REFERENCE_DIGITS:
            assert reference[position : position + 16] == literal
            checked += 1
    assert checked >= 4


# --------------------------------------------------------------------------- constants


def test_constants() -> None:
    assert pi_stream.HEX_DIGITS_PER_BATCH == 8
    assert pi_stream.GUARD_BITS == 64
    assert pi_stream.MAX_GUARD_BITS >= pi_stream.GUARD_BITS
    assert pi_stream.KEYSTREAM_BLOCK_DIGITS == 4096
    assert pi_stream.KEYSTREAM_BLOCK_DIGITS % 2 == 0


# ----------------------------------------------------------------------- golden vectors


def test_golden_64_digits_in_one_batch() -> None:
    assert pi_stream.pi_hex_digits(0, 64) == GOLDEN


@pytest.mark.parametrize("position", range(57))
def test_golden_batches_of_eight(position: int) -> None:
    assert pi_stream.pi_hex_digits(position, 8) == GOLDEN[position : position + 8]


@pytest.mark.parametrize("position", range(64))
def test_golden_single_digit(position: int) -> None:
    digit = pi_stream.pi_hex_digit(position)
    assert isinstance(digit, int)
    assert digit == int(GOLDEN[position], 16)


def test_pi_hex_int_value_and_default_count() -> None:
    assert pi_stream.pi_hex_int(0, 8) == 0x243F6A88
    assert pi_stream.pi_hex_int(0) == 0x243F6A88
    assert pi_stream.pi_hex_int(0, 1) == 0x2
    assert pi_stream.pi_hex_int(5, 3) == int(GOLDEN[5:8], 16)


@pytest.mark.parametrize("position", [12, 47])
def test_leading_zero_digit_is_kept(position: int) -> None:
    # GOLDEN[12] and GOLDEN[47] are '0': the string form must be zero-padded.
    assert GOLDEN[position] == "0"
    text = pi_stream.pi_hex_digits(position, 8)
    assert text == GOLDEN[position : position + 8]
    assert len(text) == 8
    assert pi_stream.pi_hex_int(position, 8) == int(GOLDEN[position : position + 8], 16)
    assert pi_stream.pi_hex_int(position, 8) < 16**7


def test_pi_hex_digits_is_uppercase_text() -> None:
    text = pi_stream.pi_hex_digits(0, 64)
    assert isinstance(text, str)
    assert text == text.upper()
    assert set(text) <= set("0123456789ABCDEF")


@pytest.mark.parametrize("offset", [0, 2, 16, 30])
def test_keystream_even_offsets_match_golden(offset: int) -> None:
    length = (len(GOLDEN) - offset) // 2
    expected = bytes.fromhex(GOLDEN[offset : offset + 2 * length])
    assert bytes(islice(pi_stream.keystream(offset), length)) == expected


@pytest.mark.parametrize("offset", [1, 7, 33])
def test_keystream_odd_offsets_match_golden(offset: int) -> None:
    length = (len(GOLDEN) - offset) // 2
    expected = key_bytes_from_digits(GOLDEN, offset, length)
    assert expected == bytes.fromhex(GOLDEN[offset : offset + 2 * length])
    assert bytes(islice(pi_stream.keystream(offset), length)) == expected


def test_keystream_starts_with_24_3f_6a_88() -> None:
    assert list(islice(pi_stream.keystream(0), 4)) == [0x24, 0x3F, 0x6A, 0x88]


def test_keystream_yields_ints_in_byte_range() -> None:
    values = list(islice(pi_stream.keystream(3), 40))
    assert all(isinstance(value, int) and 0 <= value <= 255 for value in values)


# ---------------------------------------------------------- far positions vs reference


@pytest.mark.parametrize("position", [1000, 4096, 9999, 16384])
def test_far_positions_match_machin_reference(reference: str, position: int) -> None:
    assert pi_stream.pi_hex_digits(position, 16) == reference[position : position + 16]


@pytest.mark.parametrize(("position", "literal"), sorted(FAR_LITERALS.items()))
def test_far_positions_match_literals(position: int, literal: str) -> None:
    assert pi_stream.pi_hex_digits(position, 16) == literal


def test_wide_batch_matches_machin_reference(reference: str) -> None:
    assert pi_stream.pi_hex_digits(0, 4096) == reference[:4096]
    assert pi_stream.pi_hex_digits(777, 1024) == reference[777 : 777 + 1024]


@pytest.mark.parametrize("offset", [0, 513, 3001, 12000])
def test_keystream_matches_machin_reference(reference: str, offset: int) -> None:
    length = 300
    expected = key_bytes_from_digits(reference, offset, length)
    assert bytes(islice(pi_stream.keystream(offset), length)) == expected
    assert b"".join(pi_stream.keystream_blocks(offset, length)) == expected


# ------------------------------------------------------------ batching vs single digit


def test_batched_output_equals_single_digit_output() -> None:
    singles = [pi_stream.pi_hex_digit(position) for position in range(208)]
    for position in range(200):
        expected = "".join(format(digit, "X") for digit in singles[position : position + 8])
        assert pi_stream.pi_hex_digits(position, 8) == expected, position


@pytest.mark.parametrize("position", [1000, 5000, 12345])
def test_batched_output_equals_single_digit_output_far(position: int) -> None:
    expected = "".join(format(pi_stream.pi_hex_digit(position + i), "X") for i in range(8))
    assert pi_stream.pi_hex_digits(position, 8) == expected


def test_single_digit_matches_machin_reference(reference: str) -> None:
    for position in (64, 999, 4097, 16000):
        assert pi_stream.pi_hex_digit(position) == int(reference[position], 16)


GROUP_POSITIONS = (0, 1, 6, 7, 8, 9, 15, 16, 17, 63, 64, 65, 255, 256, 1023)
GROUP_COUNTS = (1, 2, 7, 8, 9, 16, 33, 64)


@pytest.fixture(scope="module")
def single_digits() -> str:
    """Digits 0 to 1086 from the one-digit reference path ``pi_hex_digit``, one call each."""
    needed = max(GROUP_POSITIONS) + max(GROUP_COUNTS)
    return "".join(format(pi_stream.pi_hex_digit(position), "X") for position in range(needed))


def test_single_digit_path_matches_machin_reference(reference: str, single_digits: str) -> None:
    assert single_digits == reference[: len(single_digits)]


@pytest.mark.parametrize("position", GROUP_POSITIONS)
@pytest.mark.parametrize("count", GROUP_COUNTS)
def test_batched_output_equals_single_digit_output_across_group_boundaries(
    single_digits: str, position: int, count: int
) -> None:
    # Positions and widths around multiples of 8 (the term-group size) and around the
    # switch from the modular head of the series to its tail.
    expected = single_digits[position : position + count]
    assert len(expected) == count
    assert pi_stream.pi_hex_digits(position, count) == expected
    assert pi_stream.pi_hex_int(position, count) == int(expected, 16)


@pytest.mark.parametrize("position", [0, 7, 8, 64, 1023])
def test_forced_guard_fallback_matches_single_digit_output(
    single_digits: str, position: int
) -> None:
    for count in (1, 9, 33):
        expected = int(single_digits[position : position + count], 16)
        assert pi_stream.pi_hex_int(position, count, guard_bits=4) == expected


def test_widest_batch_matches_machin_reference_over_its_whole_length(reference: str) -> None:
    # One evaluation as wide as a crack table chunk (16384 digits) plus a margin.
    count = 16384 + 64
    assert count == REFERENCE_DIGITS
    text = pi_stream.pi_hex_digits(0, count)
    assert len(text) == count
    assert text == reference


def test_wide_batch_at_non_zero_positions_matches_machin_reference(reference: str) -> None:
    for position, count in ((1, 4096), (4095, 4097), (8191, 8192)):
        assert pi_stream.pi_hex_digits(position, count) == reference[position : position + count]


@pytest.mark.parametrize("position", [0, 37, 1000])
def test_batch_widths_are_consistent_prefixes(reference: str, position: int) -> None:
    widest = pi_stream.pi_hex_digits(position, 512)
    assert widest == reference[position : position + 512]
    for count in (1, 2, 8, 64, 512):
        text = pi_stream.pi_hex_digits(position, count)
        assert len(text) == count
        assert text == widest[:count]
        assert pi_stream.pi_hex_int(position, count) == int(widest[:count], 16)


@pytest.mark.parametrize("offset", [0, 1, 100, 601])
def test_keystream_blocks_do_not_depend_on_block_digits(reference: str, offset: int) -> None:
    length = 40
    expected = key_bytes_from_digits(reference, offset, length)
    for block_digits in (2, 8, 64, 512, 4096):
        bounded = b"".join(pi_stream.keystream_blocks(offset, length, block_digits=block_digits))
        assert bounded == expected, block_digits

        collected = bytearray()
        for block in pi_stream.keystream_blocks(offset, block_digits=block_digits):
            collected += block
            if len(collected) >= length:
                break
        assert bytes(collected[:length]) == expected, block_digits

    assert b"".join(pi_stream.keystream_blocks(offset, length)) == expected


def test_keystream_blocks_respect_block_size_and_type() -> None:
    blocks = list(pi_stream.keystream_blocks(0, 21, block_digits=8))
    assert all(isinstance(block, bytes) for block in blocks)
    assert all(1 <= len(block) <= 4 for block in blocks)
    assert sum(len(block) for block in blocks) == 21
    assert b"".join(blocks) == bytes.fromhex(GOLDEN[:42])


@pytest.mark.parametrize("length", [0, 1, 2, 3, 31, 32])
def test_keystream_blocks_yield_exactly_length_bytes(length: int) -> None:
    data = b"".join(pi_stream.keystream_blocks(0, length))
    assert data == bytes.fromhex(GOLDEN[: 2 * length])


def test_keystream_blocks_default_width_is_read_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pi_stream, "KEYSTREAM_BLOCK_DIGITS", 8)
    blocks = list(pi_stream.keystream_blocks(0, 10))
    assert [len(block) for block in blocks] == [4, 4, 2]
    assert b"".join(blocks) == bytes.fromhex(GOLDEN[:20])


def test_keystream_without_length_is_unbounded() -> None:
    blocks = list(islice(pi_stream.keystream_blocks(0, block_digits=2), 40))
    assert len(blocks) == 40
    assert b"".join(blocks) == bytes.fromhex(GOLDEN) + bytes(islice(pi_stream.keystream(64), 8))


# ------------------------------------------------------------------- guard and fallback


@pytest.mark.parametrize("position", range(41))
def test_forced_guard_fallback_gives_same_digits(position: int) -> None:
    forced = pi_stream.pi_hex_int(position, 8, guard_bits=4)
    assert forced == pi_stream.pi_hex_int(position, 8)
    assert forced == int(GOLDEN[position : position + 8], 16)


@pytest.mark.parametrize("guard_bits", [1, 4, 32, 128, 256])
def test_guard_width_does_not_change_digits(reference: str, guard_bits: int) -> None:
    for position in (0, 1000):
        value = pi_stream.pi_hex_int(position, 16, guard_bits=guard_bits)
        assert value == int(reference[position : position + 16], 16)


def test_precision_error_when_guard_cannot_be_satisfied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With 4 guard bits the acceptance interval is empty, and the ceiling forbids
    # doubling, so the guard can never be satisfied.
    monkeypatch.setattr(pi_stream, "MAX_GUARD_BITS", 4)
    with pytest.raises(PrecisionError):
        pi_stream.pi_hex_int(0, 8, guard_bits=4)
    assert issubclass(PrecisionError, EncryptorError)


# ---------------------------------------------------------------------- argument errors


def test_pi_hex_int_rejects_bad_arguments() -> None:
    with pytest.raises(ValueError):
        pi_stream.pi_hex_int(-1, 8)
    with pytest.raises(ValueError):
        pi_stream.pi_hex_int(0, 0)
    with pytest.raises(ValueError):
        pi_stream.pi_hex_int(0, -3)
    with pytest.raises(ValueError):
        pi_stream.pi_hex_int(0, 8, guard_bits=0)


def test_pi_hex_digits_rejects_bad_arguments() -> None:
    with pytest.raises(ValueError):
        pi_stream.pi_hex_digits(-1, 8)
    with pytest.raises(ValueError):
        pi_stream.pi_hex_digits(0, 0)


def test_pi_hex_digit_rejects_negative_position() -> None:
    with pytest.raises(ValueError):
        pi_stream.pi_hex_digit(-1)


def test_keystream_blocks_rejects_bad_arguments() -> None:
    with pytest.raises(ValueError):
        list(pi_stream.keystream_blocks(-1, 4))
    with pytest.raises(ValueError):
        list(pi_stream.keystream_blocks(0, -1))
    with pytest.raises(ValueError):
        list(pi_stream.keystream_blocks(0, 4, block_digits=7))
    with pytest.raises(ValueError):
        list(pi_stream.keystream_blocks(0, 4, block_digits=0))


def test_keystream_rejects_negative_offset() -> None:
    with pytest.raises(ValueError):
        next(iter(pi_stream.keystream(-1)))
