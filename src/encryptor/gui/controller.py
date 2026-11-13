"""Display-free logic behind the GUI: validation, core calls, error mapping and jobs.

This module must not import tkinter. Every function here is a thin layer over the
``classic``, ``secure``, ``crack`` and ``encoding`` modules; there is no crypto logic.
Passphrases are never logged, never stored beyond the request object, and never
appear in a ``repr`` or in an error message.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final, Generic, Literal, TypeAlias, TypeVar

from encryptor import (
    AuthenticationError,
    CrackStoppedError,
    EncryptorError,
    InputFormatError,
    MalformedCiphertextError,
    OffsetNotFoundError,
    PrecisionError,
    TruncatedCiphertextError,
    UnsupportedVersionError,
    classic,
    crack,
    encoding,
    secure,
)

T = TypeVar("T")

Action: TypeAlias = Literal["encrypt", "decrypt"]
Mode: TypeAlias = Literal["classic", "secure"]

CLASSIC_BANNER: Final[str] = (
    "Classic mode is educational and NOT secure. Use secure mode for real data."
)
POLL_INTERVAL_MS: Final[int] = 50
# Hex and decimal output is shown in lines of at most this many characters: Tk text
# layout is superlinear in the length of one logical line (100k chars in one line took
# 2.6 s; 1M chars split into 64-char lines take 0.016 s).
OUTPUT_LINE_WIDTH: Final[int] = 64

_UTF8_ERROR: Final[str] = (
    "decrypted data is not valid UTF-8 (wrong passphrase or corrupted ciphertext)"
)
_AUTH_MESSAGE: Final[str] = (
    "Wrong passphrase, or the data was corrupted or tampered with. Nothing was decrypted."
)
_MAX_OFFSET_DIGITS: Final[int] = 64
# str.translate table deleting ASCII whitespace only (space, \t, \n, \r, \v, \f).
# Other Unicode whitespace is left in place: inside the hex it is rejected as invalid,
# but at either end encoding.decode_hex's str.strip() removes it, so it is accepted.
_ASCII_WHITESPACE_DELETE: Final[dict[int, None]] = dict.fromkeys(map(ord, " \t\n\r\v\f"))


class CrackCancelledError(EncryptorError):
    """The crack search was cancelled by the user."""


@dataclass(frozen=True, slots=True)
class CipherRequest:
    """One encrypt or decrypt operation. The passphrase is excluded from ``repr``."""

    action: Action
    mode: Mode
    text: str
    passphrase: str = field(repr=False)
    decimal: bool = False


@dataclass(frozen=True, slots=True)
class CrackRequest:
    """One crack search; ``max_offset=None`` means ``classic.OFFSET_BOUND``."""

    plaintext: str
    ciphertext_hex: str
    max_offset: int | None


@dataclass(frozen=True, slots=True)
class CrackProgress:
    """Offsets ``[0, searched)`` are ruled out; ``fraction`` estimates the share of work done.

    Generating pi digits up to position d costs O(d^2) in total, so ``fraction`` is
    ``(searched / limit) ** 2``, which tracks elapsed time rather than offsets.
    """

    searched: int
    limit: int
    fraction: float


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    """A friendly dialog title and message. Never contains secrets or tracebacks."""

    title: str
    message: str


@dataclass(frozen=True, slots=True)
class Progress:
    """Job event: crack progress."""

    value: CrackProgress


@dataclass(frozen=True, slots=True)
class Done(Generic[T]):
    """Job event: the operation succeeded."""

    value: T


@dataclass(frozen=True, slots=True)
class Failed:
    """Job event: the operation failed or was cancelled.

    ``not_found`` is True only when a crack searched its whole range without a match.
    """

    error: ErrorInfo
    cancelled: bool
    not_found: bool = False


JobEvent: TypeAlias = Progress | Done[T] | Failed
_Work: TypeAlias = Callable[[threading.Event, Callable[[CrackProgress], None]], T]


def _strip_whitespace(text: str) -> str:
    """Remove ASCII whitespace, so wrapped or pasted hex parses.

    One ``str.translate`` pass: time O(n), space O(n) for the result only (no list of
    pieces). Non-ASCII whitespace is kept: interior occurrences later fail as invalid
    hex, while leading or trailing ones are removed by ``decode_hex``'s ``str.strip()``.
    """
    return text.translate(_ASCII_WHITESPACE_DELETE)


def wrap_lines(text: str, width: int = OUTPUT_LINE_WIDTH) -> str:
    """Break ``text`` into lines of at most ``width`` characters for display.

    Lines break at the last space that fits (the space is dropped), so decimal byte
    values are never split; text without a space that fits (hex) is cut every
    ``width`` characters. ``"".join(result.split())`` gives back hex input, and
    ``result.split()`` gives back the tokens of decimal input. Time O(n): each
    ``rfind`` scans at most ``width + 1`` characters of a line it then emits. Space
    O(n) for the result.
    """
    size = len(text)
    lines: list[str] = []
    start = 0
    while size - start > width:
        cut = text.rfind(" ", start, start + width + 1)
        if cut <= start:
            lines.append(text[start : start + width])
            start += width
        else:
            lines.append(text[start:cut])
            start = cut + 1
    lines.append(text[start:])
    return "\n".join(lines)


def display_text(action: Action, value: str) -> str:
    """Return how the output of ``action`` is shown: wrapped for encrypt, as is for decrypt.

    Decrypted plaintext is never altered, because Swap would feed the change back in.
    Time and space O(n).
    """
    return wrap_lines(value) if action == "encrypt" else value


def _utf8(text: str, what: str) -> bytes:
    """Encode ``text`` as UTF-8 or raise ``InputFormatError``. Time and space O(n)."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise InputFormatError(f"{what} is not valid Unicode text") from None


def prepare_cipher(request: CipherRequest) -> bytes:
    """Run every cheap check on ``request`` and return the bytes the cipher will consume.

    Encrypt gives the UTF-8 plaintext; decrypt gives the decoded hex (or decimal)
    ciphertext. No key derivation or keystream work happens here, so the GUI calls it
    on the UI thread before clearing the passphrase. Raises ``InputFormatError`` with a
    message that never echoes the passphrase. Time and space O(n).
    """
    if not request.passphrase:
        raise InputFormatError("enter a passphrase")
    if not request.text:
        raise InputFormatError("enter some input text")
    if request.decimal and request.mode != "classic":
        raise InputFormatError("decimal format is available in classic mode only")
    _utf8(request.passphrase, "passphrase")
    if request.action == "encrypt":
        return _utf8(request.text, "input")
    data = (
        encoding.decode_decimal(request.text)
        if request.decimal
        else encoding.decode_hex(_strip_whitespace(request.text))
    )
    if not data:
        raise InputFormatError("enter some input text")
    return data


def _execute_cipher(request: CipherRequest, payload: bytes) -> str:
    """Run the core cipher on ``payload`` from ``prepare_cipher(request)``.

    Time O(n) plus the core cost (scrypt, or the classic offset), space O(n).
    """
    if request.action == "encrypt":
        if request.mode == "classic":
            raw = classic.encrypt(payload, request.passphrase)
        else:
            raw = secure.encrypt(payload, request.passphrase)
        return encoding.encode_decimal(raw) if request.decimal else encoding.encode_hex(raw)
    if request.mode == "classic":
        plain = classic.decrypt(payload, request.passphrase)
    else:
        plain = secure.decrypt(payload, request.passphrase)
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        raise InputFormatError(_UTF8_ERROR) from None


def run_cipher(request: CipherRequest) -> str:
    """Validate ``request``, run it through the core and return the output text.

    Encrypt returns hex (or space-separated decimal for classic with ``decimal``);
    decrypt returns the UTF-8 plaintext. Raises ``InputFormatError`` on bad input and
    lets core errors (``AuthenticationError``, ``MalformedCiphertextError``...) through.
    Time O(n) plus the core cost (scrypt, or the classic offset), space O(n).
    """
    return _execute_cipher(request, prepare_cipher(request))


def parse_max_offset(text: str) -> int | None:
    """Parse the Max offset field: blank gives ``None``, else ASCII digits in range.

    The value must be in ``1 .. classic.OFFSET_BOUND``; anything else raises
    ``InputFormatError`` without echoing the input. Time O(len(text)).
    """
    stripped = text.strip()
    if not stripped:
        return None
    bound = classic.OFFSET_BOUND
    message = f"max offset must be a whole number from 1 to {bound}"
    if (
        not (stripped.isascii() and stripped.isdigit())
        or len(stripped) > _MAX_OFFSET_DIGITS
    ):
        raise InputFormatError(message)
    value = int(stripped)
    if not 1 <= value <= bound:
        raise InputFormatError(message)
    return value


def run_crack(
    request: CrackRequest,
    *,
    cancel: threading.Event,
    progress: Callable[[CrackProgress], None] | None = None,
) -> crack.CrackResult:
    """Search for the classic offset with one ``crack.crack`` call, with cancel and progress.

    The core calls back once per digit chunk (``crack.CRACK_PROGRESS_CHUNK_DIGITS``);
    each callback checks ``cancel`` and forwards a ``CrackProgress``, so a cancel takes
    effect within one chunk (about 1 s at the full 2**17 range). A cancel seen at any
    point, including after the core has already found or ruled out every offset,
    raises ``CrackCancelledError``. Otherwise raises ``InputFormatError`` or
    ``OffsetNotFoundError``. Ciphertext whitespace (wrapped or pasted hex) is ignored.
    Time and space as one ``crack.crack`` call (O(D^2 / w), O(D)).
    """
    plaintext = _utf8(request.plaintext, "plaintext")
    ciphertext = encoding.decode_hex(_strip_whitespace(request.ciphertext_hex))
    if not plaintext or not ciphertext:
        raise InputFormatError("enter both the known plaintext and its ciphertext")
    if len(plaintext) != len(ciphertext):
        raise InputFormatError("plaintext and ciphertext must have the same length in bytes")
    limit = request.max_offset if request.max_offset is not None else classic.OFFSET_BOUND
    if cancel.is_set():
        raise CrackCancelledError("The search was cancelled.")

    def on_chunk(tried: int, total: int) -> bool:
        if cancel.is_set():
            return False
        if progress is not None:
            ratio = tried / total
            progress(CrackProgress(tried, total, ratio * ratio))
        return True

    try:
        result = crack.crack(plaintext, ciphertext, limit, progress=on_chunk)
    except (CrackStoppedError, OffsetNotFoundError):
        if cancel.is_set():
            raise CrackCancelledError("The search was cancelled.") from None
        raise
    if cancel.is_set():
        raise CrackCancelledError("The search was cancelled.")
    return result


def format_crack_result(result: crack.CrackResult) -> str:
    """Return the three result lines the CLI prints. Time O(1)."""
    return (
        f"offset: {result.offset}\n"
        f"candidates tried: {result.candidates_tried}\n"
        f"elapsed: {result.elapsed_seconds:.3f} s"
    )


def describe_error(error: BaseException) -> ErrorInfo:
    """Map an exception to a friendly ``ErrorInfo``; subclasses are checked first.

    Unexpected exceptions report only their type name, never ``str(error)``. Time O(1).
    """
    if isinstance(error, CrackCancelledError | CrackStoppedError):
        return ErrorInfo("Cancelled", "The search was cancelled.")
    if isinstance(error, TruncatedCiphertextError):
        return ErrorInfo(
            "Incomplete ciphertext", f"{error} Paste the complete output of an encryption."
        )
    if isinstance(error, UnsupportedVersionError):
        return ErrorInfo(
            "Unsupported format", f"{error} This is not secure-mode output from this tool."
        )
    if isinstance(error, MalformedCiphertextError):
        return ErrorInfo("Invalid ciphertext", str(error))
    if isinstance(error, AuthenticationError):
        return ErrorInfo("Decryption failed", _AUTH_MESSAGE)
    if isinstance(error, InputFormatError):
        return ErrorInfo("Invalid input", str(error))
    if isinstance(error, OffsetNotFoundError):
        return ErrorInfo(
            "Offset not found",
            f"No matching offset in the searched range ({error.candidates_tried} candidates, "
            f"{error.elapsed_seconds:.3f} s).",
        )
    if isinstance(error, PrecisionError):
        return ErrorInfo("Internal error", str(error))
    if isinstance(error, EncryptorError):
        return ErrorInfo("Error", str(error))
    if isinstance(error, MemoryError):
        return ErrorInfo("Out of memory", "Not enough memory to complete the operation.")
    return ErrorInfo("Unexpected error", f"An unexpected error occurred ({type(error).__name__}).")


class Job(Generic[T]):
    """One daemon worker thread, one event queue and one cancel flag.

    The worker never touches tkinter; the UI drains events with ``poll`` from a
    ``root.after`` loop. The worker always ends with exactly one ``Done`` or ``Failed``.
    """

    def __init__(self, work: _Work[T]) -> None:
        self._events: queue.SimpleQueue[JobEvent[T]] = queue.SimpleQueue()
        self._cancel = threading.Event()
        self._work: _Work[T] | None = work
        self._thread = threading.Thread(target=self._run, name="encryptor-job", daemon=True)
        self._thread.start()

    def _report(self, value: CrackProgress) -> None:
        self._events.put(Progress(value))

    def _run(self) -> None:
        work = self._work
        self._work = None  # drop the request (and its passphrase) as soon as it runs
        event: JobEvent[T]
        try:
            if work is None:
                raise RuntimeError("job started twice")
            event = Done(work(self._cancel, self._report))
        except BaseException as error:  # every failure becomes one Failed event
            cancelled = isinstance(error, CrackCancelledError | CrackStoppedError)
            not_found = isinstance(error, OffsetNotFoundError)
            event = Failed(describe_error(error), cancelled, not_found)
        del work
        self._events.put(event)

    def poll(self) -> list[JobEvent[T]]:
        """Return every queued event without blocking. Time O(events)."""
        events: list[JobEvent[T]] = []
        while True:
            try:
                events.append(self._events.get_nowait())
            except queue.Empty:
                return events

    def cancel(self) -> None:
        """Request cancellation; a crack stops at its next digit chunk (about 1 s)."""
        self._cancel.set()

    @property
    def running(self) -> bool:
        """True while the worker thread is alive."""
        return self._thread.is_alive()


def start_cipher(request: CipherRequest, payload: bytes | None = None) -> Job[str]:
    """Run ``request`` on a worker thread and return its job.

    With ``payload`` (the result of ``prepare_cipher(request)``, already computed on the
    caller's thread) the worker skips validation and only runs the core cipher;
    without it the worker runs ``run_cipher(request)``.
    """
    if payload is None:
        return Job(lambda _cancel, _progress: run_cipher(request))
    return Job(lambda _cancel, _progress: _execute_cipher(request, payload))


def start_crack(request: CrackRequest) -> Job[crack.CrackResult]:
    """Run ``run_crack(request)`` on a worker thread, with cancel and progress."""
    return Job(lambda cancel, report: run_crack(request, cancel=cancel, progress=report))
