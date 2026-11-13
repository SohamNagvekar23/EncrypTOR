"""Classic mode: an educational running-key cipher over the hex digits of pi. NOT secure.

The keystream is pi's hex digits starting at a secret offset derived from the
passphrase, and each byte is chained: ``c[i] = p[i] ^ k[i] ^ c[i-1]``.

This cipher is NOT secure and must not protect real data: the offset space is tiny,
the keystream is public, there is no integrity check, and one known plaintext reveals
the offset (see ``encryptor.crack``). Use ``encryptor.secure`` for real data.
"""

from __future__ import annotations

import hashlib
import io
from collections.abc import Iterable, Iterator
from typing import Final

from encryptor import Buffer
from encryptor.pi_stream import keystream_blocks

# Offsets lie in [0, OFFSET_BOUND). The bound is a usability limit, not a security
# parameter. One BBP evaluation costs time roughly proportional to its digit position,
# and every keystream block pays that cost again. Measured with benchmarks/ on an
# Intel Core i7-13620H, CPython 3.13, best of 3 to 5 runs:
#   - worst case (offset 2**17 - 1): 0.18 s before the first output byte, 0.21 s for
#     a 256-byte message, 0.94 s for 4 KiB (about 4,400 key bytes per second);
#   - at offset 2**16: 0.08 s to first output, about 9,400 key bytes per second;
#   - the crack demo searches the whole range in 5.0 to 5.3 s.
# Doubling the bound to 2**18 was measured too: 0.40 s to first output, about 2,100
# key bytes per second, and 21 s for the full search (4 times longer, since the
# search grows with the square of the bound) for one extra bit of offset. So 2**17
# keeps every command interactive while the full-range attack still fits in a demo.
# No bound that keeps the cipher usable puts that search out of reach.
OFFSET_BOUND: Final[int] = 1 << 17
CHAIN_IV: Final[int] = 0xA5


def derive_offset(passphrase: str) -> int:
    """Map a passphrase to a hex-digit offset in ``[0, OFFSET_BOUND)``. NOT secure.

    SHA-256 of the UTF-8 passphrase, read as a big-endian integer, reduced modulo
    ``OFFSET_BOUND``. Time O(len(passphrase)), space O(1).
    """
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % OFFSET_BOUND


def _transform(chunks: Iterable[Buffer], blocks: Iterator[bytes], decrypt: bool) -> Iterator[bytes]:
    """Apply the chained XOR to ``chunks`` against key ``blocks``, piece by piece.

    Each piece is the overlap of an input chunk with the current key block and is
    processed with big-integer XORs: decryption is ``c ^ k ^ (prev || c[:-1])``;
    encryption is a prefix XOR of ``p ^ k`` (log-step doubling) XORed with the
    carried chain byte. Time O(n) for a fixed block size, extra space one key block
    (up to 2 KiB at the default ``KEYSTREAM_BLOCK_DIGITS``) plus one chain byte.
    """
    previous = CHAIN_IV
    key = memoryview(b"")
    key_pos = 0
    for chunk in chunks:
        view = memoryview(chunk)
        size = len(view)
        pos = 0
        while pos < size:
            if key_pos == len(key):
                key = memoryview(next(blocks))
                key_pos = 0
            take = min(size - pos, len(key) - key_pos)
            bits = 8 * take
            data = int.from_bytes(view[pos : pos + take], "big")
            mixed = data ^ int.from_bytes(key[key_pos : key_pos + take], "big")
            if decrypt:
                mixed ^= (data >> 8) | (previous << (bits - 8))
                previous = data & 0xFF
            else:
                shift = 8
                while shift < bits:
                    mixed ^= mixed >> shift
                    shift <<= 1
                # ((1 << bits) - 1) // 255 is the byte 0x01 repeated `take` times.
                mixed ^= previous * (((1 << bits) - 1) // 255)
                previous = mixed & 0xFF
            yield mixed.to_bytes(take, "big")
            pos += take
            key_pos += take


def encrypt_chunks(chunks: Iterable[Buffer], offset: int) -> Iterator[bytes]:
    """Encrypt a stream of chunks at a hex-digit ``offset``, lazily. NOT secure.

    The joined output equals ``encrypt_at_offset`` of the joined input for any split
    (empty chunks included); output chunk boundaries are unspecified. Raises
    ``ValueError`` if ``offset < 0``.

    Cipher layer: O(n) time, O(1) extra memory (one keystream block of up to
    ``KEYSTREAM_BLOCK_DIGITS / 2`` bytes, 2 KiB by default, and one chain byte
    carried between chunks). Keystream: one BBP evaluation per
    ``KEYSTREAM_BLOCK_DIGITS / 2`` bytes, each costing O((o + 2n) log(o + 2n)) for
    offset o, so total time is not linear in n for long messages.
    """
    return _transform(chunks, keystream_blocks(offset), False)


def decrypt_chunks(chunks: Iterable[Buffer], offset: int) -> Iterator[bytes]:
    """Decrypt a stream of chunks at a hex-digit ``offset``, lazily. NOT secure.

    Inverse of ``encrypt_chunks`` with the same contract and complexity. There is no
    integrity check: a wrong offset or altered data yields wrong bytes, not an error.
    """
    return _transform(chunks, keystream_blocks(offset), True)


def _collect(data: Buffer, offset: int, decrypt: bool) -> bytes:
    """Run ``_transform`` over one buffer and return the pieces as one ``bytes``.

    Pieces are written to an ``io.BytesIO`` as they are produced, so no list of
    pieces is held. Time O(n) plus the keystream cost, peak memory a little above
    the output size.
    """
    out = io.BytesIO()
    write = out.write
    for piece in _transform((data,), keystream_blocks(offset, len(data)), decrypt):
        write(piece)
    return out.getvalue()


def encrypt_at_offset(plaintext: Buffer, offset: int) -> bytes:
    """Encrypt ``plaintext`` at an explicit hex-digit ``offset``. NOT secure.

    ``c[i] = p[i] ^ k[i] ^ c[i-1]`` with ``c[-1] = CHAIN_IV``. Output length equals
    input length. Raises ``ValueError`` if ``offset < 0``.

    Cipher layer: O(n) time. Memory: one keystream block (up to 2 KiB) and one chain
    byte, plus the output, which is collected in an ``io.BytesIO`` buffer and
    returned with ``getvalue()``; the buffer grows by reallocation, so the peak is a
    little above the output size rather than exactly it (use ``encrypt_chunks`` to
    consume output incrementally in O(1) extra memory). Keystream:
    ``ceil(2n / B)`` BBP evaluations (B = ``KEYSTREAM_BLOCK_DIGITS``), each
    O((o + 2n) log(o + 2n)) for offset o.
    """
    return _collect(plaintext, offset, False)


def decrypt_at_offset(ciphertext: Buffer, offset: int) -> bytes:
    """Decrypt ``ciphertext`` at an explicit hex-digit ``offset``. NOT secure.

    ``p[i] = c[i] ^ k[i] ^ c[i-1]`` with ``c[-1] = CHAIN_IV``. Same errors and
    complexity as ``encrypt_at_offset``. No integrity check: a wrong offset returns
    different bytes, never an error.
    """
    return _collect(ciphertext, offset, True)


def encrypt(plaintext: Buffer, passphrase: str) -> bytes:
    """Encrypt with the offset derived from ``passphrase``. NOT secure.

    ``encrypt_at_offset(plaintext, derive_offset(passphrase))``; same complexity.
    """
    return encrypt_at_offset(plaintext, derive_offset(passphrase))


def decrypt(ciphertext: Buffer, passphrase: str) -> bytes:
    """Decrypt with the offset derived from ``passphrase``. NOT secure.

    A wrong passphrase cannot be detected: it returns different bytes, never an
    error. Same complexity as ``decrypt_at_offset``.
    """
    return decrypt_at_offset(ciphertext, derive_offset(passphrase))
