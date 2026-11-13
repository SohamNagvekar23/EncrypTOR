"""EncrypTOR: an educational pi-digit cipher, ChaCha20-Poly1305, and a crack demo.

The ``classic`` mode is an educational cipher and is NOT secure; ``secure`` mode is the
one to use for real data. This package module holds only the shared exception hierarchy
and the ``Buffer`` alias, and imports no submodule.
"""

from __future__ import annotations

from typing import TypeAlias

__version__ = "0.1.0"

Buffer: TypeAlias = bytes | bytearray | memoryview


class EncryptorError(Exception):
    """Base class for every failure a user can trigger; the CLI reports it in one line."""


class InputFormatError(EncryptorError):
    """Bad hex or decimal text, invalid UTF-8, or unusable crack inputs."""


class MalformedCiphertextError(EncryptorError):
    """A secure-mode blob is structurally wrong."""


class TruncatedCiphertextError(MalformedCiphertextError):
    """A secure-mode blob is shorter than the minimum valid length."""


class UnsupportedVersionError(MalformedCiphertextError):
    """A secure-mode blob carries an unknown format version byte."""


class AuthenticationError(EncryptorError):
    """Secure mode: wrong passphrase, or the data was corrupted or tampered with."""


class OffsetNotFoundError(EncryptorError):
    """The crack search found no matching offset in the searched range."""

    def __init__(self, message: str, *, candidates_tried: int, elapsed_seconds: float) -> None:
        super().__init__(message)
        self.candidates_tried = candidates_tried
        self.elapsed_seconds = elapsed_seconds


class CrackStoppedError(EncryptorError):
    """The crack search was stopped by its ``progress`` callback before it finished.

    Not an ``OffsetNotFoundError``: offsets from ``candidates_tried`` upward were never
    examined, so nothing is known about them.
    """

    def __init__(self, message: str, *, candidates_tried: int, elapsed_seconds: float) -> None:
        super().__init__(message)
        self.candidates_tried = candidates_tried
        self.elapsed_seconds = elapsed_seconds


class PrecisionError(EncryptorError):
    """The BBP precision guard could not be satisfied (practically unreachable)."""
