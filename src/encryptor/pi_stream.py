"""Hex digits of pi by the Bailey-Borwein-Plouffe (BBP) formula, and the key-byte stream.

pi = sum over k >= 0 of 16^-k * (4/(8k+1) - 2/(8k+4) - 1/(8k+5) - 1/(8k+6)).

The hex digits from position d onward (0-based, after the point; position 0 is the ``2``
of ``243F6A88...``) are the digits of frac(16^d * pi). Everything is computed with
Python integers in fixed point, never floats, so the rounding error has a provable
bound at any width.

Precision argument. For a request of c digits at position d with G guard bits, the sum
is carried with P = 4c + G fractional bits. The four BBP terms of each index k are one
positive fraction n(k)/m(k), and the terms up to index d + floor((P - 1)/4) are summed
in groups of consecutive k, each group combined exactly and floored once (the batched
path uses groups of ``_GROUP_TERMS``; the single-digit path floors each of the four
parts of every index separately). Every floor is low by less than one unit in the last
place, and the dropped tail of the series is positive and below one unit, so for the
batched path the computed sum S is never above the true value and is below it by less
than the number of groups plus one, which is at most d + P + 1. Both paths use the
looser bound E = 8 * (d + P), which also covers the signed per-part floors of the
single-digit path. A batch is accepted only if its low G bits g satisfy
E <= g < 2^G - E: then the true value lies in the same 2^G bucket as S, so no carry or
borrow can reach the extracted digits. If the guard rejects, G is doubled and the batch
recomputed, up to ``MAX_GUARD_BITS``.

This keystream drives the educational classic cipher, which is NOT secure.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

from encryptor import PrecisionError

HEX_DIGITS_PER_BATCH: Final[int] = 8
GUARD_BITS: Final[int] = 64
MAX_GUARD_BITS: Final[int] = 1024
# Key digits per BBP evaluation in the keystream (a block is up to 2 KiB of key
# bytes). The cost of reaching a far position is paid once per evaluation, so wide
# blocks spread it over more digits; beyond a few thousand digits the wide divisions
# take over and the held block keeps growing. Must be even.
KEYSTREAM_BLOCK_DIGITS: Final[int] = 4096
# Terms combined into one exact fraction per wide division (4 to 16 measure within 10%).
_GROUP_TERMS: Final[int] = 8


def _bbp_sum(position: int, precision: int) -> int:
    """Return floor-summed ``2^precision * 16^position * pi`` (fraction only), unreduced.

    The four BBP terms of index k equal n(k)/m(k) with n = 120k^2 + 151k + 47 and
    m = 512k^4 + 1024k^3 + 712k^2 + 194k + 15. ``_GROUP_TERMS`` consecutive k are
    merged into one fraction num/den scaled to the group's last index ``hi``; the
    group then costs one modular exponentiation and one wide division. A group never
    straddles ``position``, so a head group (hi <= position) keeps only the
    fractional part and a tail group is a plain shifted quotient. The last index used
    is ``position + (precision - 1) // 4``, so a tail shift is never negative and the
    dropped remainder of the series is below one unit. One floor per group means the
    result is low by less than the documented bound E, never high. The caller reduces
    the result modulo ``2^precision``.
    Time O((d + P/4) * (log d + P/w)), space O(P) bits (d = position, P = precision).
    """
    total = 0
    last = position + (precision - 1) // 4
    k = 0
    while k <= last:
        hi = min(k + _GROUP_TERMS - 1, last)
        if k <= position < hi:
            hi = position
        num = 0
        den = 1
        for i in range(k, hi + 1):
            n = (120 * i + 151) * i + 47
            m = (((512 * i + 1024) * i + 712) * i + 194) * i + 15
            num = (num << 4) * m + n * den
            den *= m
        exponent = position - hi
        if exponent >= 0:
            total += ((pow(16, exponent, den) * num % den) << precision) // den
        else:
            total += (num << (precision + 4 * exponent)) // den
        k = hi + 1
    return total


def pi_hex_int(
    position: int, count: int = HEX_DIGITS_PER_BATCH, *, guard_bits: int | None = None
) -> int:
    """Return ``count`` hex digits of pi starting at ``position`` as one integer.

    The result is in ``[0, 16**count)``, most significant digit first, and comes from
    a single BBP evaluation (repeated with a doubled guard only if the precision guard
    rejects it; see the module docstring). ``guard_bits=None`` means ``GUARD_BITS``.

    Raises ``ValueError`` for ``position < 0``, ``count < 1`` or ``guard_bits < 1``,
    and ``PrecisionError`` if the guard still fails at ``MAX_GUARD_BITS``.

    Time O((d + c) * (log d + c/w)) for d = position, c = count, w = machine word
    bits: about (d + c) / ``_GROUP_TERMS`` groups of terms, each costing one modular
    exponentiation and one P-bit division. Space O(c) bits.
    """
    if position < 0:
        raise ValueError("position must be non-negative")
    if count < 1:
        raise ValueError("count must be at least 1")
    guard = GUARD_BITS if guard_bits is None else guard_bits
    if guard < 1:
        raise ValueError("guard_bits must be at least 1")
    digit_bits = 4 * count
    while True:
        precision = digit_bits + guard
        total = _bbp_sum(position, precision) & ((1 << precision) - 1)
        guard_word = total & ((1 << guard) - 1)
        margin = 8 * (position + precision)
        if margin <= guard_word < (1 << guard) - margin:
            return total >> guard
        guard *= 2
        if guard > MAX_GUARD_BITS:
            raise PrecisionError("pi digit precision guard could not be satisfied")


def pi_hex_digits(position: int, count: int) -> str:
    """Return ``count`` hex digits of pi starting at ``position`` as uppercase text.

    Exactly ``count`` characters, zero-padded. Same errors and complexity as
    ``pi_hex_int``, plus O(c) for the string.
    """
    return format(pi_hex_int(position, count), f"0{count}X")


def pi_hex_digit(position: int) -> int:
    """Return the single hex digit of pi at ``position`` (0..15).

    A deliberately separate, straightforward BBP evaluation (it shares no code with
    ``pi_hex_int``: one modular exponentiation and one floored division for each of
    the four parts of every term) so that batched output can be checked against it.
    Uses the same fixed-point arithmetic and guard rule with one digit.

    Raises ``ValueError`` for ``position < 0`` and ``PrecisionError`` if the guard
    fails at ``MAX_GUARD_BITS``. Time O(d log d), space O(1).
    """
    if position < 0:
        raise ValueError("position must be non-negative")
    guard = GUARD_BITS
    while True:
        bits = 4 + guard
        acc = 0
        for k in range(position + 1):
            exponent = position - k
            base = 8 * k
            acc += 4 * ((pow(16, exponent, base + 1) << bits) // (base + 1))
            acc -= 2 * ((pow(16, exponent, base + 4) << bits) // (base + 4))
            acc -= (pow(16, exponent, base + 5) << bits) // (base + 5)
            acc -= (pow(16, exponent, base + 6) << bits) // (base + 6)
        k = position + 1
        shift = bits - 4
        while shift > 0:
            scale = 1 << shift
            base = 8 * k
            acc += 4 * (scale // (base + 1))
            acc -= 2 * (scale // (base + 4))
            acc -= scale // (base + 5)
            acc -= scale // (base + 6)
            k += 1
            shift -= 4
        acc %= 1 << bits
        low = acc % (1 << guard)
        margin = 8 * (position + bits)
        if margin <= low < (1 << guard) - margin:
            return acc >> guard
        guard *= 2
        if guard > MAX_GUARD_BITS:
            raise PrecisionError("pi digit precision guard could not be satisfied")


def keystream_blocks(
    offset: int, length: int | None = None, *, block_digits: int | None = None
) -> Iterator[bytes]:
    """Yield key bytes in blocks, starting ``offset`` hex digits into pi.

    Key byte i is ``16 * digit[offset + 2i] + digit[offset + 2i + 1]`` (high nibble
    first), so offset 0 yields ``24 3F 6A 88 ...``; odd offsets are valid. Each block
    comes from one BBP evaluation of at most ``block_digits`` digits
    (``None`` means ``KEYSTREAM_BLOCK_DIGITS``; must be even and >= 2). With
    ``length`` (bytes), exactly that many bytes are yielded and no evaluation asks
    for more digits than remain; with ``None`` the stream is infinite. The
    concatenated bytes do not depend on ``block_digits``.

    Raises ``ValueError`` (immediately, not on first iteration) for a negative
    offset or length or a bad ``block_digits``.

    Time: one ``pi_hex_int`` evaluation per block, each O((p + B) * (log p + B/w))
    at digit position p with B = block digits; BBP has no cheap "next digits" step,
    so every block pays the cost of its position again. Space O(B): one block of
    B/2 key bytes is held at a time (2 KiB at the default 4096 digits).
    """
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if length is not None and length < 0:
        raise ValueError("length must be non-negative")
    digits = KEYSTREAM_BLOCK_DIGITS if block_digits is None else block_digits
    if digits < 2 or digits % 2:
        raise ValueError("block_digits must be even and at least 2")
    return _blocks(offset, length, digits)


def _blocks(position: int, length: int | None, block_digits: int) -> Iterator[bytes]:
    """Generator behind ``keystream_blocks``; arguments are already validated."""
    if length is None:
        size = block_digits // 2
        while True:
            yield pi_hex_int(position, block_digits).to_bytes(size, "big")
            position += block_digits
    remaining = 2 * length
    while remaining:
        count = min(block_digits, remaining)
        yield pi_hex_int(position, count).to_bytes(count // 2, "big")
        position += count
        remaining -= count


def keystream(offset: int) -> Iterator[int]:
    """Yield key bytes (ints 0..255) forever, starting ``offset`` hex digits into pi.

    A thin wrapper that flattens ``keystream_blocks(offset)``; same per-block cost,
    O(1) per byte within a block, space O(``KEYSTREAM_BLOCK_DIGITS``) (one 2 KiB
    block of key bytes at the default).
    """
    for block in keystream_blocks(offset):
        yield from block
