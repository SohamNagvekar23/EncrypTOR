"""Secure mode: ChaCha20-Poly1305 with a scrypt-derived key.

Blob format: ``version(1) || salt(16) || nonce(12) || ciphertext || tag(16)``.

All cryptography comes from the ``cryptography`` library (``ChaCha20Poly1305`` and
``Scrypt``) plus ``os.urandom``; nothing here implements a MAC, KDF or comparison.
"""

from __future__ import annotations

import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from encryptor import (
    AuthenticationError,
    Buffer,
    EncryptorError,
    TruncatedCiphertextError,
    UnsupportedVersionError,
)

VERSION: Final[int] = 1
SALT_LEN: Final[int] = 16
NONCE_LEN: Final[int] = 12
TAG_LEN: Final[int] = 16
KEY_LEN: Final[int] = 32
HEADER_LEN: Final[int] = 1 + SALT_LEN + NONCE_LEN
MIN_BLOB_LEN: Final[int] = HEADER_LEN + TAG_LEN
# scrypt work factor: N = 2^17 with r = 8, p = 1 uses 128 * N * r bytes = 128 MiB per
# derivation. The memory cost is the brute-force resistance, so it is deliberate.
SCRYPT_N: Final[int] = 1 << 17
SCRYPT_R: Final[int] = 8
SCRYPT_P: Final[int] = 1


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive the 32-byte AEAD key with scrypt.

    Time O(SCRYPT_N * SCRYPT_R * SCRYPT_P), space ``128 * SCRYPT_N * SCRYPT_R`` bytes
    inside the library for the duration of the call. Raises ``EncryptorError`` if
    that memory cannot be allocated.
    """
    try:
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        return kdf.derive(passphrase.encode("utf-8"))
    except MemoryError:
        needed = (128 * SCRYPT_N * SCRYPT_R + (1 << 20) - 1) >> 20
        raise EncryptorError(
            f"not enough memory for key derivation (scrypt needs about {needed} MiB)"
        ) from None


def encrypt(plaintext: Buffer, passphrase: str) -> bytes:
    """Encrypt and authenticate ``plaintext`` under ``passphrase``.

    Uses a fresh random salt and nonce per call, so two encryptions of the same
    input differ. The 29-byte header (version, salt, nonce) is bound as associated
    data. Output length is ``len(plaintext) + 45``.

    Time O(n) plus the fixed scrypt cost. Space O(n): the one-shot AEAD holds the
    whole message, and the header is joined to the ciphertext with one copy; scrypt
    uses 128 MiB transiently at the default parameters.
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = bytes((VERSION,)) + salt + nonce
    key = _derive_key(passphrase, salt)
    return header + ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)


def decrypt(blob: Buffer, passphrase: str) -> bytes:
    """Verify and decrypt a blob produced by ``encrypt``.

    Raises ``TruncatedCiphertextError`` for an empty or too-short blob,
    ``UnsupportedVersionError`` for an unknown version byte (checked before the
    length), and ``AuthenticationError`` for a wrong passphrase or any modification.
    Unauthenticated plaintext is never returned.

    Time O(n) plus the fixed scrypt cost. Space O(n) for the plaintext (the blob is
    sliced through a ``memoryview``, not copied) plus scrypt's transient memory.
    """
    view = memoryview(blob)
    if len(view) == 0:
        raise TruncatedCiphertextError("ciphertext is empty")
    if view[0] != VERSION:
        raise UnsupportedVersionError("unsupported ciphertext format version")
    if len(view) < MIN_BLOB_LEN:
        raise TruncatedCiphertextError("ciphertext is too short to be valid")
    header = view[:HEADER_LEN]
    key = _derive_key(passphrase, bytes(view[1 : 1 + SALT_LEN]))
    try:
        return ChaCha20Poly1305(key).decrypt(
            view[1 + SALT_LEN : HEADER_LEN], view[HEADER_LEN:], header
        )
    except InvalidTag:
        raise AuthenticationError(
            "authentication failed: wrong passphrase, or the data was corrupted or tampered with"
        ) from None
