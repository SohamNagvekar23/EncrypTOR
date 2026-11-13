"""Known-plaintext attack on classic mode: recover the secret offset by search.

This demonstrates why classic mode is NOT secure. A known plaintext/ciphertext pair
reveals the keystream directly (``k[i] = p[i] ^ c[i] ^ c[i-1]``), and the keystream is
just a window of pi's public hex digits, so finding the offset is a substring search.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, TypeAlias

from encryptor import Buffer, CrackStoppedError, InputFormatError, OffsetNotFoundError, classic
from encryptor.pi_stream import pi_hex_digits

# A wrong offset survives a 4-byte (8 hex digit) prefix check with probability 2^-32.
CRACK_PREFIX_BYTES: Final[int] = 4
# Pi digits generated per BBP evaluation while building the search table. Wide chunks
# mean fewer evaluations (each pays for its position again), but the first chunk is
# generated in full before any candidate is tested, so a very wide chunk makes hits at
# low offsets slow.
CRACK_CHUNK_DIGITS: Final[int] = 16384
# Chunk width when a ``progress`` callback is given. The callback runs once per chunk, so
# this bounds how long a stop request waits. Each chunk pays one modular exponentiation
# per 8 BBP terms up to its position again, so narrower chunks cost more in total.
# Measured on an i7-13620H over the full 2**17 miss: 8192 runs 1.10-1.15x the time of
# ``progress=None``; 12288 runs 1.00-1.01x, and its slowest (last) chunk, the worst-case
# cancel wait, takes about 0.9 s on a cool CPU and 1.3 s when throttled.
CRACK_PROGRESS_CHUNK_DIGITS: Final[int] = 12288

ProgressCallback: TypeAlias = Callable[[int, int], bool]


@dataclass(frozen=True, slots=True)
class CrackResult:
    """Outcome of a successful search."""

    offset: int
    candidates_tried: int
    elapsed_seconds: float


def crack(
    plaintext: Buffer,
    ciphertext: Buffer,
    max_offset: int | None = None,
    *,
    progress: ProgressCallback | None = None,
) -> CrackResult:
    """Recover the classic-mode offset from a known plaintext/ciphertext pair.

    Searches offsets ``0 .. max_offset - 1`` in increasing order (``None`` means
    ``classic.OFFSET_BOUND``) and returns the first one whose keystream maps the
    plaintext to the ciphertext. The pi digits of the range are generated once, in
    chunks, into one table; each candidate is rejected on a short prefix of
    ``CRACK_PREFIX_BYTES`` key bytes and the full message is compared only on a
    prefix match. The search stops at the first full match.

    Messages shorter than ``CRACK_PREFIX_BYTES`` are searched with the whole message
    as the prefix and may match an earlier, coincidental offset (which encrypts the
    message identically).

    ``progress`` (keyword-only, optional) is called as ``progress(tried, total)``
    before the first chunk of digits is generated, after each chunk that held no
    match, and before each chunk generated to verify a prefix match against a long
    message, where offsets ``0 .. tried - 1`` are ruled out (``tried`` never decreases
    and stays below ``total``) and ``total`` is the size of the range. Returning
    ``False`` stops the search: ``crack`` then raises ``CrackStoppedError`` carrying
    ``candidates_tried=tried`` and the elapsed time, and generates no further digits.
    With a callback the table grows in ``CRACK_PROGRESS_CHUNK_DIGITS`` chunks, so a
    stop takes effect within one such chunk; with ``None`` (the default, used by the
    CLI) the search is exactly the callback-free one with ``CRACK_CHUNK_DIGITS``.

    Raises ``InputFormatError`` if either input is empty or the lengths differ,
    ``ValueError`` if ``max_offset < 1``, ``OffsetNotFoundError`` if no offset in the
    range matches, and ``CrackStoppedError`` if ``progress`` returned ``False``.

    Time O(D^2 / w) for D = digits generated (at most ``max_offset + 2m`` for an
    m-byte message; found offsets stop early); the substring search itself is O(D).
    ``progress`` adds O(D / chunk) calls. Space O(D) bytes for the digit table plus
    O(m) for the needle.
    """
    started = time.perf_counter()
    view = memoryview(ciphertext)
    size = len(view)
    if size == 0 or len(plaintext) != size:
        raise InputFormatError(
            "crack needs a non-empty plaintext and a ciphertext of the same length in bytes"
        )
    limit = classic.OFFSET_BOUND if max_offset is None else max_offset
    if limit < 1:
        raise ValueError("max_offset must be at least 1")

    # k = p ^ c ^ (CHAIN_IV || c[:-1]), computed as one big-integer XOR.
    cipher_int = int.from_bytes(view, "big")
    key_int = (
        int.from_bytes(plaintext, "big")
        ^ cipher_int
        ^ (cipher_int >> 8)
        ^ (classic.CHAIN_IV << (8 * (size - 1)))
    )
    needle = format(key_int, f"0{2 * size}X").encode("ascii")
    prefix = needle[: 2 * min(size, CRACK_PREFIX_BYTES)]

    chunk_digits = CRACK_CHUNK_DIGITS if progress is None else CRACK_PROGRESS_CHUNK_DIGITS
    table = bytearray()
    # Digits needed to test the prefix at every candidate, and the full needle at
    # the last candidate.
    prefix_limit = limit - 1 + len(prefix)
    needle_limit = limit - 1 + len(needle)

    def extend(target: int) -> None:
        count = min(chunk_digits, target - len(table))
        table.extend(pi_hex_digits(len(table), count).encode("ascii"))

    def stopped(tried: int) -> CrackStoppedError:
        elapsed = time.perf_counter() - started
        return CrackStoppedError(
            f"search stopped after {tried} of {limit} candidates ({elapsed:.3f} s)",
            candidates_tried=tried,
            elapsed_seconds=elapsed,
        )

    start = 0
    while True:
        end = min(len(table), prefix_limit)
        hit = table.find(prefix, start, end)
        if hit >= 0:
            while len(table) < hit + len(needle):
                # Offsets below the hit are ruled out; let a long needle be stopped.
                if progress is not None and not progress(hit, limit):
                    raise stopped(hit)
                extend(needle_limit)
            if table.startswith(needle, hit):
                return CrackResult(hit, hit + 1, time.perf_counter() - started)
            start = hit + 1
            continue
        if end >= prefix_limit:
            elapsed = time.perf_counter() - started
            raise OffsetNotFoundError(
                f"offset not found in [0, {limit}) after {limit} candidates ({elapsed:.3f} s)",
                candidates_tried=limit,
                elapsed_seconds=elapsed,
            )
        # Resume where a prefix straddling the old table end could begin.
        start = max(start, end - len(prefix) + 1)
        if progress is not None and not progress(start, limit):
            raise stopped(start)
        extend(prefix_limit)
