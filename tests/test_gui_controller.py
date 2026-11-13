"""Tests for encryptor.gui.controller: the display-free logic behind the GUI.

Nothing here needs tkinter or a display. An autouse fixture lowers ``secure.SCRYPT_N`` and
the ``small_bound`` fixture shrinks ``classic.OFFSET_BOUND``, as the other test modules do,
so the suite runs in seconds. The controller must therefore read both constants at call
time (``secure.SCRYPT_N`` is read by the core; ``classic.OFFSET_BOUND`` by the controller).

The crack tests that need several progress reports use ``max_offset=30000``: with
``crack.CRACK_PROGRESS_CHUNK_DIGITS`` (12288) the core reports before the first chunk and
after each of the first two chunks.

Tests that replace ``crack.crack`` patch the attribute on the ``encryptor.crack`` module,
so the controller has to call it as ``crack.crack(...)`` (module attribute looked up at
call time), not through a ``from encryptor.crack import crack`` alias.
"""

from __future__ import annotations

import dataclasses
import itertools
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from typing import TypeVar

import pytest

# isort: off
# Until src/encryptor/gui exists, isort would file ``encryptor.gui`` under third-party
# imports; the block is pinned so the order is the same before and after implementation.
from encryptor import (
    AuthenticationError,
    Buffer,
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
from encryptor.gui import controller

# isort: on

T = TypeVar("T")

SMALL_BOUND = 4096
FAST_SCRYPT_N = 1 << 10
JOB_TIMEOUT_SECONDS = 30.0

PASSPHRASE = "zebra quilt"
OTHER_PASSPHRASE = "walrus tango"
TEXT = "hello, world"
UNICODE_TEXT = "naïve café 日本語 жщэ π \U0001f512\U0001f680"
LONG_TEXT = "The quick brown fox jumps over the lazy dog. " * 40
CRACK_MESSAGE = "Known plaintext: meet me at the old bridge at nine."

# A range that spans three progress chunks of crack.CRACK_PROGRESS_CHUNK_DIGITS (12288).
CHUNKED_LIMIT = 30000
OFFSET_IN_SECOND_CHUNK = 13000
OFFSET_OUT_OF_RANGE = 35000

UTF8_ERROR = "decrypted data is not valid UTF-8 (wrong passphrase or corrupted ciphertext)"


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secure, "SCRYPT_N", FAST_SCRYPT_N)


@pytest.fixture
def small_bound(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(classic, "OFFSET_BOUND", SMALL_BOUND)
    return SMALL_BOUND


def cipher_request(
    action: controller.Action,
    mode: controller.Mode,
    text: str,
    passphrase: str = PASSPHRASE,
    decimal: bool = False,
) -> controller.CipherRequest:
    return controller.CipherRequest(
        action=action, mode=mode, text=text, passphrase=passphrase, decimal=decimal
    )


def crack_pair(offset: int) -> tuple[str, str]:
    """Return ``CRACK_MESSAGE`` and the hex of its classic ciphertext at ``offset``."""
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), offset)
    return CRACK_MESSAGE, ciphertext.hex()


def crack_request(offset: int, max_offset: int | None) -> controller.CrackRequest:
    plaintext, ciphertext_hex = crack_pair(offset)
    return controller.CrackRequest(
        plaintext=plaintext, ciphertext_hex=ciphertext_hex, max_offset=max_offset
    )


def is_terminal(event: object) -> bool:
    return isinstance(event, controller.Done | controller.Failed)


def wait_for_job(job: controller.Job[T]) -> list[controller.JobEvent[T]]:
    """Poll ``job`` until its worker has finished and return every event, in order.

    Fails the test if the job does not finish in ``JOB_TIMEOUT_SECONDS`` or if it does
    not end with exactly one terminal event (``Done`` or ``Failed``) in last position.
    """
    events: list[controller.JobEvent[T]] = []
    deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
    while True:
        events.extend(job.poll())
        if events and is_terminal(events[-1]) and not job.running:
            break
        if time.monotonic() > deadline:
            pytest.fail(f"job did not finish within {JOB_TIMEOUT_SECONDS} s; events: {events!r}")
        time.sleep(0.005)
    events.extend(job.poll())
    assert sum(is_terminal(event) for event in events) == 1
    assert is_terminal(events[-1])
    assert job.poll() == []
    assert job.running is False
    return events


# ------------------------------------------------------------------- 1. no tkinter import


def test_importing_controller_does_not_import_tkinter() -> None:
    code = (
        "import sys\n"
        "import encryptor.gui.controller\n"
        "print(sorted(name for name in sys.modules if name.split('.')[0] in "
        "('tkinter', '_tkinter')))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "[]"


# ---------------------------------------------------------------------------- constants


def test_constants() -> None:
    assert controller.CLASSIC_BANNER == (
        "Classic mode is educational and NOT secure. Use secure mode for real data."
    )
    assert controller.POLL_INTERVAL_MS == 50
    assert controller.OUTPUT_LINE_WIDTH == 64
    # The staged search is gone: one core call reports progress per chunk.
    assert not hasattr(controller, "CRACK_FIRST_STAGE")
    assert not hasattr(controller, "crack_stages")


def test_crack_cancelled_error_is_an_encryptor_error() -> None:
    assert issubclass(controller.CrackCancelledError, EncryptorError)
    assert not issubclass(controller.CrackCancelledError, OffsetNotFoundError)


# ---------------------------------------------------------------- 2. classic round trips


@pytest.mark.parametrize("decimal", [False, True], ids=["hex", "decimal"])
@pytest.mark.parametrize(
    "text", ["a", TEXT, UNICODE_TEXT, LONG_TEXT], ids=["one-char", "ascii", "non-ascii", "long"]
)
def test_classic_round_trip(small_bound: int, text: str, decimal: bool) -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "classic", text, decimal=decimal))
    assert isinstance(encrypted, str)
    # The controller adds nothing of its own: same bytes and encoding as the core.
    raw = classic.encrypt(text.encode("utf-8"), PASSPHRASE)
    expected = encoding.encode_decimal(raw) if decimal else encoding.encode_hex(raw)
    assert encrypted == expected
    decrypted = controller.run_cipher(
        cipher_request("decrypt", "classic", encrypted, decimal=decimal)
    )
    assert decrypted == text


def test_classic_decimal_output_is_space_separated_byte_values(small_bound: int) -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "classic", TEXT, decimal=True))
    tokens = encrypted.split(" ")
    assert len(tokens) == len(TEXT.encode("utf-8"))
    assert all(token.isdigit() and 0 <= int(token) <= 255 for token in tokens)


@pytest.mark.parametrize("decimal", [False, True], ids=["hex", "decimal"])
def test_classic_decrypt_ignores_surrounding_whitespace(small_bound: int, decimal: bool) -> None:
    # A text widget or a paste commonly adds a trailing newline.
    encrypted = controller.run_cipher(cipher_request("encrypt", "classic", TEXT, decimal=decimal))
    padded = f"  {encrypted}\n"
    assert (
        controller.run_cipher(cipher_request("decrypt", "classic", padded, decimal=decimal)) == TEXT
    )


def test_classic_non_ascii_passphrase(small_bound: int) -> None:
    passphrase = "pässwörd \U0001f511 日本"
    encrypted = controller.run_cipher(cipher_request("encrypt", "classic", TEXT, passphrase))
    assert controller.run_cipher(cipher_request("decrypt", "classic", encrypted, passphrase)) == (
        TEXT
    )


# ------------------------------------------------------------------ 3. secure round trip


@pytest.mark.parametrize("text", ["a", TEXT, UNICODE_TEXT, LONG_TEXT])
def test_secure_round_trip(text: str) -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "secure", text))
    assert isinstance(encrypted, str)
    blob = bytes.fromhex(encrypted)
    assert encrypted == blob.hex()
    assert len(blob) == len(text.encode("utf-8")) + secure.MIN_BLOB_LEN
    assert secure.decrypt(blob, PASSPHRASE) == text.encode("utf-8")
    assert controller.run_cipher(cipher_request("decrypt", "secure", encrypted)) == text


def test_secure_two_encryptions_differ() -> None:
    first = controller.run_cipher(cipher_request("encrypt", "secure", TEXT))
    second = controller.run_cipher(cipher_request("encrypt", "secure", TEXT))
    assert first != second
    assert controller.run_cipher(cipher_request("decrypt", "secure", first)) == TEXT
    assert controller.run_cipher(cipher_request("decrypt", "secure", second)) == TEXT


def test_secure_decrypts_core_output() -> None:
    blob = secure.encrypt(UNICODE_TEXT.encode("utf-8"), PASSPHRASE)
    request = cipher_request("decrypt", "secure", blob.hex().upper() + "\n")
    assert controller.run_cipher(request) == UNICODE_TEXT


# ------------------------------------------------------------------------- 4. validation


@pytest.mark.parametrize("action", ["encrypt", "decrypt"])
@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_empty_passphrase_is_rejected(
    small_bound: int, action: controller.Action, mode: controller.Mode
) -> None:
    with pytest.raises(InputFormatError):
        controller.run_cipher(cipher_request(action, mode, "00ff", passphrase=""))


@pytest.mark.parametrize("action", ["encrypt", "decrypt"])
@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_empty_text_is_rejected(
    small_bound: int, action: controller.Action, mode: controller.Mode
) -> None:
    with pytest.raises(InputFormatError):
        controller.run_cipher(cipher_request(action, mode, ""))


@pytest.mark.parametrize("action", ["encrypt", "decrypt"])
def test_decimal_with_secure_mode_is_rejected(action: controller.Action) -> None:
    with pytest.raises(InputFormatError):
        controller.run_cipher(cipher_request(action, "secure", "1 2 3", decimal=True))


@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_lone_surrogate_text_is_rejected(small_bound: int, mode: controller.Mode) -> None:
    with pytest.raises(InputFormatError):
        controller.run_cipher(cipher_request("encrypt", mode, "bad \ud800 text"))


@pytest.mark.parametrize("action", ["encrypt", "decrypt"])
@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_lone_surrogate_passphrase_is_rejected(
    small_bound: int, action: controller.Action, mode: controller.Mode
) -> None:
    with pytest.raises(InputFormatError):
        controller.run_cipher(cipher_request(action, mode, "00ff", passphrase="pass\udfffword"))


def test_validation_errors_do_not_echo_the_passphrase_or_text() -> None:
    secret = "hunter2-very-secret"
    payload = "payload-that-must-not-be-echoed"
    with pytest.raises(InputFormatError) as excinfo:
        controller.run_cipher(cipher_request("encrypt", "secure", payload, secret, decimal=True))
    assert secret not in str(excinfo.value)
    assert payload not in str(excinfo.value)


# ------------------------------------------------------- 5. bad ciphertext text, classic


# Inner whitespace ("12 34") is accepted: wrapped output and pasted hex must decrypt.
@pytest.mark.parametrize("bad_hex", ["zz", "abc", "12 3","0x1f", "\uff46\uff46"])
@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_bad_hex_on_decrypt_is_rejected(
    small_bound: int, mode: controller.Mode, bad_hex: str
) -> None:
    with pytest.raises(InputFormatError) as excinfo:
        controller.run_cipher(cipher_request("decrypt", mode, bad_hex))
    assert bad_hex not in str(excinfo.value)


@pytest.mark.parametrize("bad_decimal", ["256", "1 2 x", "-1 2", "1,2,3", "1_0", "1.5", "١٢"])
def test_bad_decimal_on_decrypt_is_rejected(small_bound: int, bad_decimal: str) -> None:
    with pytest.raises(InputFormatError):
        controller.run_cipher(cipher_request("decrypt", "classic", bad_decimal, decimal=True))


def test_classic_wrong_passphrase_gives_different_text_or_a_clean_error(small_bound: int) -> None:
    assert classic.derive_offset(PASSPHRASE) != classic.derive_offset(OTHER_PASSPHRASE)
    encrypted = controller.run_cipher(cipher_request("encrypt", "classic", LONG_TEXT))
    try:
        decrypted = controller.run_cipher(
            cipher_request("decrypt", "classic", encrypted, OTHER_PASSPHRASE)
        )
    except InputFormatError as error:
        assert str(error) == UTF8_ERROR
    else:
        assert decrypted != LONG_TEXT


def test_classic_decrypt_to_invalid_utf8_is_an_input_format_error(small_bound: int) -> None:
    # Ciphertext whose correct decryption is not UTF-8: the same failure a wrong
    # passphrase usually causes, forced deterministically.
    ciphertext = classic.encrypt(b"\xff\xfe\xfd valid tail", PASSPHRASE)
    with pytest.raises(InputFormatError) as excinfo:
        controller.run_cipher(cipher_request("decrypt", "classic", ciphertext.hex()))
    assert str(excinfo.value) == UTF8_ERROR
    assert not isinstance(excinfo.value, UnicodeError)


# ------------------------------------------------------------------- 6. secure failures


def test_secure_wrong_passphrase_raises_authentication_error() -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "secure", TEXT))
    with pytest.raises(AuthenticationError):
        controller.run_cipher(cipher_request("decrypt", "secure", encrypted, OTHER_PASSPHRASE))


@pytest.mark.parametrize("bit", [8, 135, 136, 231, 232, -1])
def test_secure_flipped_bit_raises_authentication_error(bit: int) -> None:
    blob = bytearray(bytes.fromhex(controller.run_cipher(cipher_request("encrypt", "secure", "x"))))
    position = bit % (len(blob) * 8)
    blob[position // 8] ^= 1 << (position % 8)
    with pytest.raises(AuthenticationError):
        controller.run_cipher(cipher_request("decrypt", "secure", blob.hex()))


@pytest.mark.parametrize("length", [1, 29, 44])
def test_secure_short_blob_raises_truncated_error(length: int) -> None:
    short = (b"\x01" + bytes(length - 1)).hex()
    with pytest.raises(TruncatedCiphertextError):
        controller.run_cipher(cipher_request("decrypt", "secure", short))


@pytest.mark.parametrize("version", [0, 2, 0xFF])
def test_secure_bad_version_raises_unsupported_version_error(version: int) -> None:
    blob = bytearray(secure.encrypt(b"versioned", PASSPHRASE))
    blob[0] = version
    with pytest.raises(UnsupportedVersionError):
        controller.run_cipher(cipher_request("decrypt", "secure", blob.hex()))


# ---------------------------------------------------------------------- 7. error mapping


class CustomEncryptorError(EncryptorError):
    """An EncryptorError subclass the table does not name: falls to the generic row."""


class CustomBaseError(BaseException):
    """Not an ``Exception``: the last row must still catch it."""


AUTH_MESSAGE = (
    "Wrong passphrase, or the data was corrupted or tampered with. Nothing was decrypted."
)

ERROR_TABLE: list[tuple[BaseException, str, str]] = [
    (controller.CrackCancelledError(), "Cancelled", "The search was cancelled."),
    (
        controller.CrackCancelledError("with a custom text"),
        "Cancelled",
        "The search was cancelled.",
    ),
    (
        TruncatedCiphertextError("ciphertext is too short to be valid"),
        "Incomplete ciphertext",
        "ciphertext is too short to be valid Paste the complete output of an encryption.",
    ),
    (
        UnsupportedVersionError("unsupported ciphertext format version"),
        "Unsupported format",
        "unsupported ciphertext format version This is not secure-mode output from this tool.",
    ),
    (MalformedCiphertextError("blob is malformed"), "Invalid ciphertext", "blob is malformed"),
    (AuthenticationError("authentication failed: core wording"), "Decryption failed", AUTH_MESSAGE),
    (
        InputFormatError("invalid hex input: expected an even number of hex digits (0-9, a-f)"),
        "Invalid input",
        "invalid hex input: expected an even number of hex digits (0-9, a-f)",
    ),
    (
        OffsetNotFoundError("core wording", candidates_tried=4096, elapsed_seconds=1.23456),
        "Offset not found",
        "No matching offset in the searched range (4096 candidates, 1.235 s).",
    ),
    (
        OffsetNotFoundError("core wording", candidates_tried=131072, elapsed_seconds=0.0),
        "Offset not found",
        "No matching offset in the searched range (131072 candidates, 0.000 s).",
    ),
    (PrecisionError("precision guard failed"), "Internal error", "precision guard failed"),
    (
        EncryptorError("not enough memory for key derivation (scrypt needs about 128 MiB)"),
        "Error",
        "not enough memory for key derivation (scrypt needs about 128 MiB)",
    ),
    (CustomEncryptorError("some other failure"), "Error", "some other failure"),
    (MemoryError("boom"), "Out of memory", "Not enough memory to complete the operation."),
    (MemoryError(), "Out of memory", "Not enough memory to complete the operation."),
    (
        RuntimeError("sensitive detail"),
        "Unexpected error",
        "An unexpected error occurred (RuntimeError).",
    ),
    (
        ValueError("sensitive detail"),
        "Unexpected error",
        "An unexpected error occurred (ValueError).",
    ),
    (
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "sensitive detail"),
        "Unexpected error",
        "An unexpected error occurred (UnicodeDecodeError).",
    ),
    (
        KeyboardInterrupt("sensitive detail"),
        "Unexpected error",
        "An unexpected error occurred (KeyboardInterrupt).",
    ),
    (
        CustomBaseError("sensitive detail"),
        "Unexpected error",
        "An unexpected error occurred (CustomBaseError).",
    ),
]


@pytest.mark.parametrize(
    ("error", "title", "message"),
    ERROR_TABLE,
    ids=[f"{index}-{type(row[0]).__name__}" for index, row in enumerate(ERROR_TABLE)],
)
def test_describe_error_table(error: BaseException, title: str, message: str) -> None:
    info = controller.describe_error(error)
    assert isinstance(info, controller.ErrorInfo)
    assert info == controller.ErrorInfo(title=title, message=message)


def test_describe_error_checks_subclasses_before_their_base() -> None:
    malformed = controller.describe_error(MalformedCiphertextError("m")).title
    assert malformed == "Invalid ciphertext"
    assert controller.describe_error(TruncatedCiphertextError("t")).title != malformed
    assert controller.describe_error(UnsupportedVersionError("u")).title != malformed
    generic = controller.describe_error(EncryptorError("e")).title
    assert generic == "Error"
    for specific in (
        controller.CrackCancelledError(),
        TruncatedCiphertextError("t"),
        UnsupportedVersionError("u"),
        MalformedCiphertextError("m"),
        AuthenticationError("a"),
        InputFormatError("i"),
        OffsetNotFoundError("o", candidates_tried=1, elapsed_seconds=0.0),
        PrecisionError("p"),
    ):
        assert controller.describe_error(specific).title != generic


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("sensitive detail: hunter2"),
        KeyError("sensitive detail: hunter2"),
        OSError(5, "sensitive detail: hunter2"),
        CustomBaseError("sensitive detail: hunter2"),
    ],
    ids=lambda error: type(error).__name__,
)
def test_unexpected_error_message_never_contains_str_of_error(error: BaseException) -> None:
    info = controller.describe_error(error)
    assert info.title == "Unexpected error"
    assert str(error) not in info.message
    assert "hunter2" not in info.message
    assert "sensitive" not in info.message
    assert "Traceback" not in info.message
    assert type(error).__name__ in info.message


def test_describe_error_maps_real_core_failures() -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "secure", TEXT))
    with pytest.raises(AuthenticationError) as auth:
        controller.run_cipher(cipher_request("decrypt", "secure", encrypted, OTHER_PASSPHRASE))
    assert controller.describe_error(auth.value) == controller.ErrorInfo(
        "Decryption failed", AUTH_MESSAGE
    )
    with pytest.raises(TruncatedCiphertextError) as truncated:
        controller.run_cipher(cipher_request("decrypt", "secure", "01"))
    info = controller.describe_error(truncated.value)
    assert info.title == "Incomplete ciphertext"
    assert info.message == f"{truncated.value} Paste the complete output of an encryption."


def test_error_info_is_a_frozen_dataclass() -> None:
    info = controller.ErrorInfo(title="t", message="m")
    assert (info.title, info.message) == ("t", "m")
    with pytest.raises(dataclasses.FrozenInstanceError):
        info.title = "other"  # type: ignore[misc]


# --------------------------------------------------------------------- 8. request repr


def test_cipher_request_repr_hides_the_passphrase() -> None:
    secret = "hunter2-very-secret"
    request = cipher_request("encrypt", "classic", TEXT, secret, decimal=True)
    assert request.passphrase == secret
    for rendered in (repr(request), str(request), f"{request}", f"{request!r}"):
        assert secret not in rendered
        assert "hunter2" not in rendered
    assert secret not in repr([request])
    assert secret not in repr({"request": request})


def test_cipher_request_fields_and_defaults() -> None:
    request = controller.CipherRequest(
        action="decrypt", mode="secure", text="00", passphrase=PASSPHRASE
    )
    assert (request.action, request.mode, request.text, request.decimal) == (
        "decrypt",
        "secure",
        "00",
        False,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.passphrase = "other"  # type: ignore[misc]


# ------------------------------------------------------------------ 9. parse_max_offset


@pytest.mark.parametrize("blank", ["", " ", "   ", "\t", "\n", " \t\n "])
def test_parse_max_offset_blank_is_none(blank: str) -> None:
    assert controller.parse_max_offset(blank) is None


@pytest.mark.parametrize(
    ("text", "expected"), [("1", 1), ("2", 2), ("512", 512), ("0512", 512), ("4096", 4096)]
)
def test_parse_max_offset_valid(small_bound: int, text: str, expected: int) -> None:
    assert controller.parse_max_offset(text) == expected


def test_parse_max_offset_accepts_the_real_bound() -> None:
    assert controller.parse_max_offset(str(classic.OFFSET_BOUND)) == classic.OFFSET_BOUND == 1 << 17


@pytest.mark.parametrize(
    "text",
    [
        "0",
        "00",
        "-1",
        "-0",
        "+5",
        "1_000",
        "١٢٣",  # Arabic-Indic digits
        "\uff14\uff12",  # fullwidth digits
        "²",  # superscript two: str.isdigit() is true, int() fails
        "1.5",
        "1e3",
        "0x10",
        "abc",
        "12 34",
        "4097",  # one above the patched bound
        "131072",
        "9" * 5000,  # longer than the interpreter's int-conversion digit limit
    ],
)
def test_parse_max_offset_invalid(small_bound: int, text: str) -> None:
    with pytest.raises(InputFormatError):
        controller.parse_max_offset(text)


def test_parse_max_offset_above_the_real_bound_is_rejected() -> None:
    with pytest.raises(InputFormatError):
        controller.parse_max_offset(str(classic.OFFSET_BOUND + 1))


# ------------------------------------------------------------- 10. output line wrapping


@pytest.mark.parametrize("length", [0, 1, 63, 64, 65, 128, 1000])
def test_wrap_lines_hex_has_fixed_width_lines_and_unwraps(length: int) -> None:
    hex_text = ("0123456789abcdef" * 80)[:length]
    wrapped = controller.wrap_lines(hex_text)
    lines = wrapped.split("\n")
    assert all(len(line) == controller.OUTPUT_LINE_WIDTH for line in lines[:-1])
    assert 0 <= len(lines[-1]) <= controller.OUTPUT_LINE_WIDTH
    assert "".join(lines) == hex_text
    assert "".join(wrapped.split()) == hex_text


def test_wrap_lines_decimal_breaks_only_on_spaces() -> None:
    raw = encoding.encode_decimal(bytes(range(256)) * 3)
    wrapped = controller.wrap_lines(raw)
    lines = wrapped.split("\n")
    assert len(lines) > 1
    assert all(0 < len(line) <= controller.OUTPUT_LINE_WIDTH for line in lines)
    assert all(line == line.strip() for line in lines)
    # No byte value is split across two lines.
    assert wrapped.split() == raw.split(" ")
    assert " ".join(lines) == raw


def test_wrap_lines_custom_width() -> None:
    assert controller.wrap_lines("abcdefgh", 3) == "abc\ndef\ngh"
    assert controller.wrap_lines("1 22 333 4", 4) == "1 22\n333\n4"


def test_display_text_wraps_encrypt_output_only() -> None:
    long_hex = "ab" * 100
    assert controller.display_text("encrypt", long_hex) == controller.wrap_lines(long_hex)
    plain = "x" * 200
    assert controller.display_text("decrypt", plain) == plain


@pytest.mark.parametrize("decimal", [False, True], ids=["hex", "decimal"])
def test_wrapped_classic_output_decrypts(small_bound: int, decimal: bool) -> None:
    encrypted = controller.run_cipher(
        cipher_request("encrypt", "classic", LONG_TEXT, decimal=decimal)
    )
    shown = controller.display_text("encrypt", encrypted)
    assert "\n" in shown
    decrypted = controller.run_cipher(
        cipher_request("decrypt", "classic", shown, decimal=decimal)
    )
    assert decrypted == LONG_TEXT


def test_wrapped_secure_output_decrypts() -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "secure", LONG_TEXT))
    shown = controller.display_text("encrypt", encrypted)
    assert "\n" in shown
    assert controller.run_cipher(cipher_request("decrypt", "secure", shown)) == LONG_TEXT


def test_decrypt_hex_ignores_inner_whitespace_and_crlf(small_bound: int) -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "classic", LONG_TEXT))
    pasted = "\r\n".join(encrypted[i : i + 50] for i in range(0, len(encrypted), 50))
    pasted = f"\t{pasted} \n"
    assert controller.run_cipher(cipher_request("decrypt", "classic", pasted)) == LONG_TEXT
    assert controller.prepare_cipher(cipher_request("decrypt", "classic", pasted)) == (
        bytes.fromhex(encrypted)
    )


def test_decrypt_hex_still_rejects_bad_digits_after_whitespace_removal() -> None:
    with pytest.raises(InputFormatError):
        controller.prepare_cipher(cipher_request("decrypt", "secure", "ab c\nzz"))
    with pytest.raises(InputFormatError):
        controller.prepare_cipher(cipher_request("decrypt", "secure", "ab c"))


def test_run_crack_accepts_wrapped_ciphertext() -> None:
    plaintext, ciphertext_hex = crack_pair(40)
    wrapped = controller.wrap_lines(ciphertext_hex, 16)
    assert "\n" in wrapped
    request = controller.CrackRequest(plaintext=plaintext, ciphertext_hex=wrapped, max_offset=64)
    assert controller.run_crack(request, cancel=threading.Event()).offset == 40


# ------------------------------------------------------------------- 11. run_crack hits


@pytest.mark.parametrize("offset", [0, 1, 777, 4095])
def test_run_crack_recovers_offset_in_default_range(small_bound: int, offset: int) -> None:
    request = crack_request(offset, None)
    seen: list[controller.CrackProgress] = []
    result = controller.run_crack(request, cancel=threading.Event(), progress=seen.append)
    assert isinstance(result, crack.CrackResult)
    reference = crack.crack(CRACK_MESSAGE.encode("utf-8"), bytes.fromhex(request.ciphertext_hex))
    assert result.offset == reference.offset == offset
    assert result.candidates_tried == reference.candidates_tried == offset + 1
    assert isinstance(result.elapsed_seconds, float)
    assert result.elapsed_seconds >= 0
    assert all(item.limit == small_bound for item in seen)


def test_run_crack_recovers_passphrase_offset(small_bound: int) -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "classic", CRACK_MESSAGE))
    request = controller.CrackRequest(
        plaintext=CRACK_MESSAGE, ciphertext_hex=encrypted, max_offset=None
    )
    result = controller.run_crack(request, cancel=threading.Event())
    assert result.offset == classic.derive_offset(PASSPHRASE)


def test_run_crack_with_explicit_max_offset() -> None:
    result = controller.run_crack(crack_request(300, 301), cancel=threading.Event())
    assert (result.offset, result.candidates_tried) == (300, 301)


def test_run_crack_accepts_hex_with_surrounding_whitespace_and_upper_case() -> None:
    plaintext, ciphertext_hex = crack_pair(12)
    request = controller.CrackRequest(
        plaintext=plaintext, ciphertext_hex=f" {ciphertext_hex.upper()}\n", max_offset=64
    )
    assert controller.run_crack(request, cancel=threading.Event()).offset == 12


def test_run_crack_hit_in_a_later_chunk_reports_progress_first() -> None:
    request = crack_request(OFFSET_IN_SECOND_CHUNK, CHUNKED_LIMIT)
    seen: list[controller.CrackProgress] = []
    started = time.perf_counter()
    result = controller.run_crack(request, cancel=threading.Event(), progress=seen.append)
    wall = time.perf_counter() - started
    reference = crack.crack(
        CRACK_MESSAGE.encode("utf-8"), bytes.fromhex(request.ciphertext_hex), CHUNKED_LIMIT
    )
    assert result.offset == reference.offset == OFFSET_IN_SECOND_CHUNK
    assert result.candidates_tried == reference.candidates_tried == OFFSET_IN_SECOND_CHUNK + 1
    assert 0 < result.elapsed_seconds <= wall
    # At least one report rules out a whole first chunk before the hit.
    assert any(0 < item.searched <= OFFSET_IN_SECOND_CHUNK for item in seen)
    assert all(item.limit == CHUNKED_LIMIT for item in seen)


def test_run_crack_non_ascii_plaintext() -> None:
    plaintext = UNICODE_TEXT
    ciphertext = classic.encrypt_at_offset(plaintext.encode("utf-8"), 40)
    request = controller.CrackRequest(
        plaintext=plaintext, ciphertext_hex=ciphertext.hex(), max_offset=64
    )
    assert controller.run_crack(request, cancel=threading.Event()).offset == 40


def test_run_crack_calls_the_core_once_with_a_progress_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_crack = crack.crack
    calls: list[int | None] = []

    def recording(
        plaintext: Buffer,
        ciphertext: Buffer,
        max_offset: int | None = None,
        *,
        progress: Callable[[int, int], bool] | None = None,
    ) -> crack.CrackResult:
        assert progress is not None
        calls.append(max_offset)
        return real_crack(plaintext, ciphertext, max_offset, progress=progress)

    monkeypatch.setattr(crack, "crack", recording)
    with pytest.raises(OffsetNotFoundError):
        controller.run_crack(
            crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT), cancel=threading.Event()
        )
    assert calls == [CHUNKED_LIMIT]


# ----------------------------------------------------------- 12. run_crack out of range


def test_run_crack_out_of_range_in_default_range(small_bound: int) -> None:
    with pytest.raises(OffsetNotFoundError) as excinfo:
        controller.run_crack(crack_request(5000, None), cancel=threading.Event())
    assert excinfo.value.candidates_tried == small_bound
    assert isinstance(excinfo.value.elapsed_seconds, float)
    assert excinfo.value.elapsed_seconds >= 0


def test_run_crack_out_of_range_reports_limit_and_monotonic_progress() -> None:
    seen: list[controller.CrackProgress] = []
    started = time.perf_counter()
    with pytest.raises(OffsetNotFoundError) as excinfo:
        controller.run_crack(
            crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT),
            cancel=threading.Event(),
            progress=seen.append,
        )
    wall = time.perf_counter() - started
    error = excinfo.value
    assert error.candidates_tried == CHUNKED_LIMIT
    assert 0 <= error.elapsed_seconds <= wall

    assert len(seen) >= 3
    assert all(isinstance(item, controller.CrackProgress) for item in seen)
    assert all(item.limit == CHUNKED_LIMIT for item in seen)
    searched = [item.searched for item in seen]
    fractions = [item.fraction for item in seen]
    assert all(low <= high for low, high in itertools.pairwise(searched))
    assert all(low <= high for low, high in itertools.pairwise(fractions))
    assert all(0.0 <= fraction <= 1.0 for fraction in fractions)
    assert searched[-1] > searched[0]
    # Each report is at most one progress chunk after the previous one.
    steps = [high - low for low, high in itertools.pairwise(searched)]
    assert max(steps) <= crack.CRACK_PROGRESS_CHUNK_DIGITS


def test_run_crack_without_progress_callback() -> None:
    with pytest.raises(OffsetNotFoundError):
        controller.run_crack(
            crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT), cancel=threading.Event()
        )


@pytest.mark.parametrize(
    ("plaintext", "ciphertext_hex"),
    [
        ("abc", "zz"),
        ("abc", "abc"),
        ("", ""),
        ("abc", ""),
        ("", "00ff"),
        ("abc", "00ff"),
        ("bad \ud800 text", "00ff"),
    ],
    ids=["bad-hex", "odd-hex", "both-empty", "empty-hex", "empty-text", "unequal", "surrogate"],
)
def test_run_crack_bad_input_is_an_input_format_error(plaintext: str, ciphertext_hex: str) -> None:
    request = controller.CrackRequest(
        plaintext=plaintext, ciphertext_hex=ciphertext_hex, max_offset=16
    )
    with pytest.raises(InputFormatError):
        controller.run_crack(request, cancel=threading.Event())


def test_format_crack_result_matches_the_cli_lines() -> None:
    text = controller.format_crack_result(crack.CrackResult(5, 6, 0.25))
    assert text.splitlines() == ["offset: 5", "candidates tried: 6", "elapsed: 0.250 s"]
    text = controller.format_crack_result(crack.CrackResult(131071, 131072, 5.12345))
    assert text.splitlines() == ["offset: 131071", "candidates tried: 131072", "elapsed: 5.123 s"]


# ---------------------------------------------------------------------------- 13. cancel


def test_run_crack_cancelled_before_start_never_calls_the_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_run(*args: object, **kwargs: object) -> crack.CrackResult:
        raise AssertionError("crack.crack was called although cancel was already set")

    request = crack_request(5, 64)
    monkeypatch.setattr(crack, "crack", must_not_run)
    cancel = threading.Event()
    cancel.set()
    seen: list[controller.CrackProgress] = []
    with pytest.raises(controller.CrackCancelledError):
        controller.run_crack(request, cancel=cancel, progress=seen.append)
    assert seen == []
    assert cancel.is_set()


@pytest.mark.parametrize("cancel_at", [1, 2, 3])
def test_run_crack_cancel_stops_at_the_next_chunk(cancel_at: int) -> None:
    request = crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT)
    cancel = threading.Event()
    seen: list[controller.CrackProgress] = []

    def on_progress(item: controller.CrackProgress) -> None:
        seen.append(item)
        if len(seen) == cancel_at:
            cancel.set()

    with pytest.raises(controller.CrackCancelledError):
        controller.run_crack(request, cancel=cancel, progress=on_progress)
    # The core sees the cancel at its next chunk boundary: no report after the cancel.
    assert len(seen) == cancel_at


def test_run_crack_cancel_late_is_cancelled_not_offset_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The cancel lands after the core's last chunk check: the core ends with
    # OffsetNotFoundError, but the user cancelled, so the job must report cancelled.
    cancel = threading.Event()

    def late_miss(
        plaintext: Buffer,
        ciphertext: Buffer,
        max_offset: int | None = None,
        *,
        progress: Callable[[int, int], bool] | None = None,
    ) -> crack.CrackResult:
        assert progress is not None and max_offset is not None
        assert progress(max_offset - 1, max_offset) is True
        cancel.set()
        raise OffsetNotFoundError("miss", candidates_tried=max_offset, elapsed_seconds=0.0)

    monkeypatch.setattr(crack, "crack", late_miss)
    with pytest.raises(controller.CrackCancelledError):
        controller.run_crack(crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT), cancel=cancel)


def test_run_crack_cancel_on_the_last_report_of_a_real_search() -> None:
    # A real miss: cancelling on its very last progress report must still end as
    # cancelled, never as "offset not found".
    request = crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT)
    reports: list[controller.CrackProgress] = []
    with pytest.raises(OffsetNotFoundError):
        controller.run_crack(request, cancel=threading.Event(), progress=reports.append)
    last = reports[-1].searched
    cancel = threading.Event()

    def on_progress(item: controller.CrackProgress) -> None:
        if item.searched >= last:
            cancel.set()

    with pytest.raises(controller.CrackCancelledError):
        controller.run_crack(request, cancel=cancel, progress=on_progress)


def test_run_crack_cancel_after_a_hit_is_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    cancel = threading.Event()

    def late_hit(*args: object, **kwargs: object) -> crack.CrackResult:
        cancel.set()
        return crack.CrackResult(3, 4, 0.0)

    monkeypatch.setattr(crack, "crack", late_hit)
    with pytest.raises(controller.CrackCancelledError):
        controller.run_crack(crack_request(3, 16), cancel=cancel)


def test_crack_stopped_error_from_the_core_maps_to_cancelled() -> None:
    error = CrackStoppedError("stopped", candidates_tried=5, elapsed_seconds=0.1)
    assert controller.describe_error(error) == controller.ErrorInfo(
        "Cancelled", "The search was cancelled."
    )


def test_crack_cancelled_error_maps_to_the_cancelled_row() -> None:
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(controller.CrackCancelledError) as excinfo:
        controller.run_crack(crack_request(5, 64), cancel=cancel)
    assert controller.describe_error(excinfo.value) == controller.ErrorInfo(
        "Cancelled", "The search was cancelled."
    )


# ------------------------------------------------------------------------------ 14. jobs


def test_start_cipher_delivers_one_done_with_the_round_trip_text(small_bound: int) -> None:
    encrypt_job = controller.start_cipher(cipher_request("encrypt", "classic", UNICODE_TEXT))
    assert isinstance(encrypt_job, controller.Job)
    events = wait_for_job(encrypt_job)
    assert len(events) == 1
    done = events[0]
    assert isinstance(done, controller.Done)
    assert done.value == classic.encrypt(UNICODE_TEXT.encode("utf-8"), PASSPHRASE).hex()

    decrypt_job = controller.start_cipher(cipher_request("decrypt", "classic", done.value))
    assert wait_for_job(decrypt_job) == [controller.Done(UNICODE_TEXT)]


def test_start_cipher_secure_round_trip() -> None:
    events = wait_for_job(controller.start_cipher(cipher_request("encrypt", "secure", TEXT)))
    assert len(events) == 1
    done = events[0]
    assert isinstance(done, controller.Done)
    decrypt_job = controller.start_cipher(cipher_request("decrypt", "secure", done.value))
    assert wait_for_job(decrypt_job) == [controller.Done(TEXT)]


def test_start_cipher_wrong_passphrase_delivers_one_failed() -> None:
    encrypted = controller.run_cipher(cipher_request("encrypt", "secure", TEXT))
    job = controller.start_cipher(cipher_request("decrypt", "secure", encrypted, OTHER_PASSPHRASE))
    assert wait_for_job(job) == [
        controller.Failed(
            error=controller.ErrorInfo("Decryption failed", AUTH_MESSAGE), cancelled=False
        )
    ]


def test_start_cipher_validation_failure_delivers_one_failed() -> None:
    job = controller.start_cipher(cipher_request("encrypt", "secure", TEXT, passphrase=""))
    events = wait_for_job(job)
    assert len(events) == 1
    failed = events[0]
    assert isinstance(failed, controller.Failed)
    assert failed.cancelled is False
    assert failed.error.title == "Invalid input"
    assert failed.error.message


def test_start_cipher_bad_hex_failure_carries_the_core_message() -> None:
    events = wait_for_job(controller.start_cipher(cipher_request("decrypt", "secure", "zz")))
    assert events == [
        controller.Failed(
            error=controller.ErrorInfo(
                "Invalid input",
                "invalid hex input: expected an even number of hex digits (0-9, a-f)",
            ),
            cancelled=False,
        )
    ]


def test_job_is_running_while_the_worker_is_blocked_and_poll_does_not_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocked_encrypt(plaintext: Buffer, passphrase: str) -> bytes:
        entered.set()
        assert release.wait(JOB_TIMEOUT_SECONDS)
        return b"\x00\xff"

    monkeypatch.setattr(classic, "encrypt", blocked_encrypt)
    job = controller.start_cipher(cipher_request("encrypt", "classic", TEXT))
    try:
        assert entered.wait(JOB_TIMEOUT_SECONDS), "the worker never called classic.encrypt"
        assert job.running is True
        started = time.monotonic()
        assert job.poll() == []
        assert time.monotonic() - started < 1.0
    finally:
        release.set()
    assert wait_for_job(job) == [controller.Done("00ff")]


def test_start_crack_delivers_done_with_the_result() -> None:
    events = wait_for_job(controller.start_crack(crack_request(300, 512)))
    *progress, done = events
    # The core reports once before generating the first chunk.
    assert all(isinstance(event, controller.Progress) for event in progress)
    assert isinstance(done, controller.Done)
    assert isinstance(done.value, crack.CrackResult)
    assert (done.value.offset, done.value.candidates_tried) == (300, 301)


def test_start_crack_delivers_progress_events_before_done() -> None:
    job = controller.start_crack(crack_request(OFFSET_IN_SECOND_CHUNK, CHUNKED_LIMIT))
    events = wait_for_job(job)
    *progress, done = events
    assert progress
    reports = [event.value for event in progress if isinstance(event, controller.Progress)]
    assert len(reports) == len(progress)
    searched = [item.searched for item in reports]
    assert all(low <= high for low, high in itertools.pairwise(searched))
    assert all(item.limit == CHUNKED_LIMIT for item in reports)
    assert isinstance(done, controller.Done)
    assert done.value.offset == OFFSET_IN_SECOND_CHUNK


def test_start_crack_out_of_range_delivers_failed_not_cancelled() -> None:
    events = wait_for_job(controller.start_crack(crack_request(600, 512)))
    *progress, failed = events
    assert all(isinstance(event, controller.Progress) for event in progress)
    assert isinstance(failed, controller.Failed)
    assert failed.cancelled is False
    assert failed.error.title == "Offset not found"
    assert failed.error.message.startswith(
        "No matching offset in the searched range (512 candidates, "
    )


def test_start_crack_cancel_ends_in_failed_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    # The core blocks inside its first chunk until the test has called job.cancel(); the
    # next chunk check must then stop it. No timing assumption is involved.
    entered = threading.Event()
    release = threading.Event()
    answers: list[bool] = []

    def blocked_search(
        plaintext: Buffer,
        ciphertext: Buffer,
        max_offset: int | None = None,
        *,
        progress: Callable[[int, int], bool] | None = None,
    ) -> crack.CrackResult:
        assert progress is not None and max_offset is not None
        answers.append(progress(0, max_offset))
        entered.set()
        assert release.wait(JOB_TIMEOUT_SECONDS)
        answers.append(progress(8192, max_offset))
        if not answers[-1]:
            raise CrackStoppedError("stopped", candidates_tried=8192, elapsed_seconds=0.0)
        raise AssertionError("the cancel was not seen at the chunk boundary")

    request = crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT)
    monkeypatch.setattr(crack, "crack", blocked_search)
    job = controller.start_crack(request)
    try:
        assert entered.wait(JOB_TIMEOUT_SECONDS), "the worker never called crack.crack"
        assert job.running is True
        job.cancel()
    finally:
        release.set()
    events = wait_for_job(job)
    assert events[-1] == controller.Failed(
        error=controller.ErrorInfo("Cancelled", "The search was cancelled."), cancelled=True
    )
    assert all(isinstance(event, controller.Progress) for event in events[:-1])
    assert answers == [True, False]


def test_start_crack_real_search_cancel_latency_is_one_chunk() -> None:
    # A real miss over the full default range (2**17). Cancel after the second progress
    # report (deep in the search); the job must end as cancelled about one chunk later,
    # long before a full search (several seconds) would finish.
    job = controller.start_crack(crack_request(classic.OFFSET_BOUND + 500, None))
    deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
    events: list[controller.JobEvent[crack.CrackResult]] = []
    while sum(isinstance(event, controller.Progress) for event in events) < 2:
        events.extend(job.poll())
        if time.monotonic() > deadline:
            pytest.fail("no progress report")
        time.sleep(0.002)
    job.cancel()
    cancelled_at = time.monotonic()
    while not events or not is_terminal(events[-1]):
        events.extend(job.poll())
        if time.monotonic() > deadline:
            pytest.fail("the cancelled job did not finish")
        time.sleep(0.002)
    latency = time.monotonic() - cancelled_at
    failed = events[-1]
    assert isinstance(failed, controller.Failed)
    assert failed.cancelled is True
    assert latency < 3.0


def test_start_crack_real_search_can_be_cancelled() -> None:
    # No patching: cancel is requested right after the start, long before the three
    # chunks of an unfindable offset can complete.
    job = controller.start_crack(crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT))
    job.cancel()
    events = wait_for_job(job)
    failed = events[-1]
    assert isinstance(failed, controller.Failed)
    assert failed.cancelled is True
    assert failed.error.title == "Cancelled"


def test_cancel_after_the_job_finished_is_harmless() -> None:
    job = controller.start_crack(crack_request(3, 16))
    events = wait_for_job(job)
    assert isinstance(events[-1], controller.Done)
    job.cancel()
    job.cancel()
    assert job.poll() == []
    assert job.running is False


@pytest.mark.parametrize(
    "error",
    [RuntimeError("sensitive detail"), ZeroDivisionError("sensitive detail"), CustomBaseError()],
    ids=lambda error: type(error).__name__,
)
def test_start_cipher_unexpected_worker_exception_still_ends_in_failed(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    def broken_encrypt(plaintext: Buffer, passphrase: str) -> bytes:
        raise error

    monkeypatch.setattr(classic, "encrypt", broken_encrypt)
    events = wait_for_job(controller.start_cipher(cipher_request("encrypt", "classic", TEXT)))
    assert events == [
        controller.Failed(
            error=controller.ErrorInfo(
                "Unexpected error", f"An unexpected error occurred ({type(error).__name__})."
            ),
            cancelled=False,
        )
    ]


def test_start_crack_unexpected_worker_exception_still_ends_in_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_crack(*args: object, **kwargs: object) -> crack.CrackResult:
        raise LookupError("sensitive detail")

    request = crack_request(3, 16)
    monkeypatch.setattr(crack, "crack", broken_crack)
    events = wait_for_job(controller.start_crack(request))
    assert len(events) == 1
    failed = events[0]
    assert isinstance(failed, controller.Failed)
    assert failed.cancelled is False
    assert failed.error == controller.ErrorInfo(
        "Unexpected error", "An unexpected error occurred (LookupError)."
    )
    assert "sensitive" not in failed.error.message


def test_start_cipher_memory_error_is_reported_as_out_of_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exhausted(plaintext: Buffer, passphrase: str) -> bytes:
        raise MemoryError("boom")

    monkeypatch.setattr(secure, "encrypt", exhausted)
    events = wait_for_job(controller.start_cipher(cipher_request("encrypt", "secure", TEXT)))
    assert events == [
        controller.Failed(
            error=controller.ErrorInfo(
                "Out of memory", "Not enough memory to complete the operation."
            ),
            cancelled=False,
        )
    ]


def test_job_events_never_carry_the_passphrase(small_bound: int) -> None:
    secret = "hunter2-very-secret"
    ok = wait_for_job(controller.start_cipher(cipher_request("encrypt", "classic", TEXT, secret)))
    bad = wait_for_job(controller.start_cipher(cipher_request("decrypt", "classic", "zz", secret)))
    assert secret not in repr(ok)
    assert secret not in repr(bad)


# ------------------------------------------- S5. cheap validation before the worker runs


@pytest.mark.parametrize(
    ("request_args", "message"),
    [
        (("encrypt", "secure", TEXT, ""), "enter a passphrase"),
        (("encrypt", "classic", "", PASSPHRASE), "enter some input text"),
        (("decrypt", "secure", "", PASSPHRASE), "enter some input text"),
        (("decrypt", "secure", "   ", PASSPHRASE), "enter some input text"),
        (("decrypt", "secure", "zz", PASSPHRASE), "invalid hex input"),
        (("decrypt", "secure", "abc", PASSPHRASE), "invalid hex input"),
    ],
)
def test_prepare_cipher_rejects_bad_input(
    request_args: tuple[controller.Action, controller.Mode, str, str], message: str
) -> None:
    with pytest.raises(InputFormatError, match=message):
        controller.prepare_cipher(cipher_request(*request_args))


def test_prepare_cipher_rejects_bad_decimal_and_decimal_in_secure_mode() -> None:
    with pytest.raises(InputFormatError, match="invalid decimal input"):
        controller.prepare_cipher(cipher_request("decrypt", "classic", "1 2 300", decimal=True))
    with pytest.raises(InputFormatError, match="classic mode only"):
        controller.prepare_cipher(cipher_request("encrypt", "secure", TEXT, decimal=True))


def test_prepare_cipher_returns_the_payload_bytes() -> None:
    assert controller.prepare_cipher(cipher_request("encrypt", "classic", "héllo")) == (
        "héllo".encode()
    )
    assert controller.prepare_cipher(cipher_request("decrypt", "classic", " 0aFF ")) == (
        b"\x0a\xff"
    )
    assert controller.prepare_cipher(
        cipher_request("decrypt", "classic", "10 255", decimal=True)
    ) == bytes([10, 255])


def test_start_cipher_with_prepared_payload_round_trips(small_bound: int) -> None:
    request = cipher_request("encrypt", "classic", UNICODE_TEXT)
    events = wait_for_job(controller.start_cipher(request, controller.prepare_cipher(request)))
    done = events[-1]
    assert isinstance(done, controller.Done)
    back = cipher_request("decrypt", "classic", done.value)
    events = wait_for_job(controller.start_cipher(back, controller.prepare_cipher(back)))
    assert events[-1] == controller.Done(UNICODE_TEXT)


# ------------------------------------------------------ GUI round 2 (R5/Q3, R6)


@pytest.mark.parametrize("separator", ["\u00a0", "\u2003", "\u3000", "\x1c", "\x85"])
def test_non_ascii_or_control_whitespace_is_invalid_hex(separator: str) -> None:
    # Only ASCII whitespace (space, \t, \n, \r, \v, \f) is stripped from hex input.
    with pytest.raises(InputFormatError, match="invalid hex input"):
        controller.prepare_cipher(cipher_request("decrypt", "secure", f"0a{separator}ff"))
    request = controller.CrackRequest(
        plaintext="ab", ciphertext_hex=f"0a{separator}ff", max_offset=16
    )
    with pytest.raises(InputFormatError, match="invalid hex input"):
        controller.run_crack(request, cancel=threading.Event())


def test_every_ascii_whitespace_is_stripped_from_hex() -> None:
    assert controller.prepare_cipher(
        cipher_request("decrypt", "classic", " 0a\t\n\r\x0b\x0cff ")
    ) == b"\x0a\xff"


def test_failed_not_found_flag_is_set_only_for_offset_not_found() -> None:
    events = wait_for_job(
        controller.start_crack(crack_request(OFFSET_OUT_OF_RANGE, CHUNKED_LIMIT))
    )
    failed = events[-1]
    assert isinstance(failed, controller.Failed)
    assert failed.not_found is True
    assert failed.cancelled is False
    other = wait_for_job(controller.start_cipher(cipher_request("decrypt", "secure", "zz")))
    assert isinstance(other[-1], controller.Failed)
    assert other[-1].not_found is False
