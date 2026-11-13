"""Tests for encryptor.cli: the argparse front end.

``main`` is called in-process. Because decrypt writes raw bytes through
``sys.stdout.buffer``, the tests replace ``sys.stdin``, ``sys.stdout`` and ``sys.stderr``
with ``io.TextIOWrapper`` objects over ``io.BytesIO`` (which have a real ``.buffer``) and
read the underlying bytes afterwards, so text writes and buffer writes are both captured.
Two subprocess tests exercise the real process streams and exit codes.
"""

from __future__ import annotations

import argparse
import errno
import getpass
import io
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Protocol

import pytest

from encryptor import classic, cli, encoding, secure

SMALL_BOUND = 4096
FAST_SCRYPT_N = 1 << 10

PASSPHRASE = "zebra quilt"
TEXT = "hello, world"
UNICODE_TEXT = "naïve café 日本語 \U0001f512"
CRACK_MESSAGE = "Known plaintext: meet me at the old bridge at nine."


@dataclass(frozen=True)
class CliResult:
    """Exit code and the raw bytes written to each stream by one ``main`` call."""

    code: int
    stdout: bytes
    stderr: bytes

    @property
    def out(self) -> str:
        return self.stdout.decode("utf-8")

    @property
    def err(self) -> str:
        return self.stderr.decode("utf-8")


class Runner(Protocol):
    def __call__(self, argv: list[str], stdin: bytes = b"") -> CliResult: ...


@pytest.fixture(autouse=True)
def fast_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cheap scrypt and a small classic offset range; fail loudly on an unexpected prompt."""

    def unexpected_prompt(prompt: str = "", stream: object = None) -> str:
        raise AssertionError("getpass.getpass was called without --prompt")

    monkeypatch.setattr(secure, "SCRYPT_N", FAST_SCRYPT_N)
    monkeypatch.setattr(classic, "OFFSET_BOUND", SMALL_BOUND)
    monkeypatch.setattr(getpass, "getpass", unexpected_prompt)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> Runner:
    """Call ``cli.main(argv)`` with replaced standard streams and return what it wrote."""

    def _run(argv: list[str], stdin: bytes = b"") -> CliResult:
        out_raw = io.BytesIO()
        err_raw = io.BytesIO()
        out = io.TextIOWrapper(out_raw, encoding="utf-8", newline="\n")
        err = io.TextIOWrapper(err_raw, encoding="utf-8", newline="\n")
        with monkeypatch.context() as patch:
            patch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8"))
            patch.setattr(sys, "stdout", out)
            patch.setattr(sys, "stderr", err)
            code = cli.main(argv)
            out.flush()
            err.flush()
        assert isinstance(code, int)
        return CliResult(code, out_raw.getvalue(), err_raw.getvalue())

    return _run


def normalized(text: str) -> str:
    """Collapse whitespace so argparse line wrapping cannot split a phrase."""
    return " ".join(text.split())


def assert_clean_error(result: CliResult, code: int) -> None:
    """A failed run: the given exit code, nothing on stdout, one clean error line.

    Runtime failures (codes other than 2) are reported by ``main`` itself as
    ``encryptor: error: ...``. Usage errors come from argparse, whose subparsers
    name themselves in the prefix (``encryptor crack: error: ...``), so for code 2
    either form is accepted.
    """
    assert result.code == code
    assert result.stdout == b""
    assert "Traceback" not in result.err
    pattern = r"encryptor( \w+)?: error: \S" if code == 2 else r"encryptor: error: \S"
    assert any(re.match(pattern, line) for line in result.err.splitlines())


def encrypt_args(mode: str, *extra: str) -> list[str]:
    return ["encrypt", "--mode", mode, "--passphrase", PASSPHRASE, *extra]


def decrypt_args(mode: str, *extra: str) -> list[str]:
    return ["decrypt", "--mode", mode, "--passphrase", PASSPHRASE, *extra]


# ------------------------------------------------------------------ constants and parser


def test_exit_code_constants() -> None:
    assert cli.EXIT_OK == 0
    assert cli.EXIT_ERROR == 1
    assert cli.EXIT_USAGE == 2
    assert cli.EXIT_INPUT == 3
    assert cli.EXIT_AUTH == 4
    assert cli.EXIT_NOT_FOUND == 5


def test_classic_notice_text() -> None:
    assert "NOT secure" in cli.CLASSIC_NOTICE
    assert "classic" in cli.CLASSIC_NOTICE
    assert "\n" not in cli.CLASSIC_NOTICE


def test_build_parser() -> None:
    parser = cli.build_parser()
    assert isinstance(parser, argparse.ArgumentParser)
    assert parser.prog == "encryptor"
    args = parser.parse_args(["encrypt", "--mode", "classic", "--passphrase", "pw", "hi"])
    assert args.command == "encrypt"
    assert args.mode == "classic"
    args = parser.parse_args(["crack", "--plaintext", "a", "--ciphertext", "00"])
    assert args.command == "crack"
    assert args.max_offset is None


# -------------------------------------------------------------- argument and stdin input


@pytest.mark.parametrize("text", [TEXT, UNICODE_TEXT, "a", ""])
def test_classic_argument_round_trip(run: Runner, text: str) -> None:
    encrypted = run(encrypt_args("classic", text))
    assert encrypted.code == 0
    expected_hex = encoding.encode_hex(classic.encrypt(text.encode("utf-8"), PASSPHRASE))
    assert encrypted.out == expected_hex + "\n"

    decrypted = run(decrypt_args("classic", expected_hex))
    assert decrypted.code == 0
    assert decrypted.stdout == text.encode("utf-8") + b"\n"


@pytest.mark.parametrize("text", [TEXT, UNICODE_TEXT, "a", ""])
def test_secure_argument_round_trip(run: Runner, text: str) -> None:
    encrypted = run(encrypt_args("secure", text))
    assert encrypted.code == 0
    assert encrypted.err == ""
    assert encrypted.out.endswith("\n")
    blob_hex = encrypted.out[:-1]
    assert re.fullmatch(r"[0-9a-f]*", blob_hex)
    blob = bytes.fromhex(blob_hex)
    assert len(blob) == len(text.encode("utf-8")) + 45
    assert blob[0] == 1
    assert secure.decrypt(blob, PASSPHRASE) == text.encode("utf-8")

    decrypted = run(decrypt_args("secure", blob_hex))
    assert decrypted.code == 0
    assert decrypted.err == ""
    assert decrypted.stdout == text.encode("utf-8") + b"\n"


@pytest.mark.parametrize("mode", ["classic", "secure"])
@pytest.mark.parametrize("dash", [["-"], []], ids=["dash", "omitted"])
def test_stdin_round_trip(run: Runner, mode: str, dash: list[str]) -> None:
    data = UNICODE_TEXT.encode("utf-8")
    encrypted = run(encrypt_args(mode, *dash), stdin=data)
    assert encrypted.code == 0
    assert re.fullmatch(r"[0-9a-f]+\n", encrypted.out)

    # Hex arrives on stdin with its trailing newline, as it would through a pipe.
    decrypted = run(decrypt_args(mode, *dash), stdin=encrypted.stdout)
    assert decrypted.code == 0
    assert decrypted.stdout == data + b"\n"


def test_stdin_and_argument_give_the_same_classic_output(run: Runner) -> None:
    from_argument = run(encrypt_args("classic", TEXT))
    from_stdin = run(encrypt_args("classic", "-"), stdin=TEXT.encode("utf-8"))
    assert from_argument.code == from_stdin.code == 0
    assert from_argument.stdout == from_stdin.stdout


def test_encrypt_stdin_is_taken_exactly(run: Runner) -> None:
    # No newline stripping on encrypt input.
    data = b"line one\nline two\n"
    encrypted = run(encrypt_args("classic"), stdin=data)
    assert encrypted.code == 0
    assert encrypted.out == encoding.encode_hex(classic.encrypt(data, PASSPHRASE)) + "\n"
    decrypted = run(decrypt_args("classic", encrypted.out.strip()))
    assert decrypted.stdout == data + b"\n"


def test_empty_stdin_encrypts_to_empty_classic_output(run: Runner) -> None:
    encrypted = run(encrypt_args("classic"), stdin=b"")
    assert encrypted.code == 0
    assert encrypted.out == "\n"


def test_decrypt_accepts_uppercase_hex_and_surrounding_whitespace(run: Runner) -> None:
    hex_text = encoding.encode_hex(classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE))
    assert run(decrypt_args("classic", hex_text.upper())).stdout == TEXT.encode() + b"\n"
    padded = f"  {hex_text}\r\n".encode("ascii")
    assert run(decrypt_args("classic"), stdin=padded).stdout == TEXT.encode() + b"\n"


def test_stdout_holds_only_the_result(run: Runner) -> None:
    encrypted = run(encrypt_args("classic", TEXT))
    assert encrypted.out.count("\n") == 1
    assert re.fullmatch(r"[0-9a-f]+\n", encrypted.out)
    assert len(encrypted.out) == 2 * len(TEXT) + 1
    assert "WARNING" not in encrypted.out
    decrypted = run(decrypt_args("classic", encrypted.out.strip()))
    assert decrypted.stdout == TEXT.encode("utf-8") + b"\n"


# ---------------------------------------------------------------------------- --decimal


def test_decimal_encrypt_output(run: Runner) -> None:
    result = run(encrypt_args("classic", "--decimal", TEXT))
    assert result.code == 0
    ciphertext = classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE)
    assert result.out == encoding.encode_decimal(ciphertext) + "\n"
    values = [int(token) for token in result.out.split()]
    assert bytes(values) == ciphertext
    assert result.out.rstrip("\n") == " ".join(str(value) for value in ciphertext)


def test_decimal_round_trip_argument_and_stdin(run: Runner) -> None:
    encrypted = run(encrypt_args("classic", "--decimal", UNICODE_TEXT))
    assert encrypted.code == 0
    from_argument = run(decrypt_args("classic", "--decimal", encrypted.out.strip()))
    assert from_argument.code == 0
    assert from_argument.stdout == UNICODE_TEXT.encode("utf-8") + b"\n"
    from_stdin = run(decrypt_args("classic", "--decimal", "-"), stdin=encrypted.stdout)
    assert from_stdin.code == 0
    assert from_stdin.stdout == UNICODE_TEXT.encode("utf-8") + b"\n"


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
def test_decimal_with_secure_mode_is_a_usage_error(run: Runner, command: str) -> None:
    result = run([command, "--mode", "secure", "--decimal", "--passphrase", PASSPHRASE, "00"])
    assert_clean_error(result, 2)


@pytest.mark.parametrize("bad", ["256 1", "1,2", "-1", "0a ff", "1_0"])
def test_bad_decimal_input(run: Runner, bad: str) -> None:
    result = run(decrypt_args("classic", "--decimal"), stdin=bad.encode("ascii"))
    assert_clean_error(result, 3)


# ---------------------------------------------------------------------------- bad input


@pytest.mark.parametrize("mode", ["classic", "secure"])
@pytest.mark.parametrize("bad", ["zzqqzzqq", "abc", "12 3g"])
def test_bad_hex_input(run: Runner, mode: str, bad: str) -> None:
    from_argument = run(decrypt_args(mode, bad))
    assert_clean_error(from_argument, 3)
    from_stdin = run(decrypt_args(mode, "-"), stdin=bad.encode("ascii"))
    assert_clean_error(from_stdin, 3)


def test_bad_hex_is_not_echoed(run: Runner) -> None:
    result = run(decrypt_args("classic", "zzqqzzqq"))
    assert_clean_error(result, 3)
    assert "zzqq" not in result.err


def test_non_ascii_bytes_on_decrypt_stdin(run: Runner) -> None:
    result = run(decrypt_args("classic", "-"), stdin=b"\xff\xfe\x00")
    assert_clean_error(result, 3)


def test_invalid_utf8_on_encrypt_stdin(run: Runner) -> None:
    for mode in ("classic", "secure"):
        result = run(encrypt_args(mode, "-"), stdin=b"caf\xe9 \xff")
        assert_clean_error(result, 3)


@pytest.mark.parametrize("hex_text", ["", "01", "01" * 44])
def test_truncated_secure_blob(run: Runner, hex_text: str) -> None:
    assert_clean_error(run(decrypt_args("secure", hex_text)), 3)


def test_unknown_secure_version(run: Runner) -> None:
    blob = bytearray(secure.encrypt(b"versioned", PASSPHRASE))
    blob[0] = 2
    assert_clean_error(run(decrypt_args("secure", blob.hex())), 3)


def test_wrong_secure_passphrase(run: Runner) -> None:
    blob_hex = secure.encrypt(TEXT.encode("utf-8"), PASSPHRASE).hex()
    result = run(["decrypt", "--mode", "secure", "--passphrase", "not the passphrase", blob_hex])
    assert_clean_error(result, 4)
    assert "not the passphrase" not in result.err
    assert TEXT not in result.err


def test_tampered_secure_blob(run: Runner) -> None:
    blob = bytearray(secure.encrypt(TEXT.encode("utf-8"), PASSPHRASE))
    blob[-1] ^= 0x01
    assert_clean_error(run(decrypt_args("secure", blob.hex())), 4)
    blob[-1] ^= 0x01
    blob[5] ^= 0x80
    assert_clean_error(run(decrypt_args("secure", blob.hex())), 4)


def test_wrong_classic_passphrase_differs_or_fails(run: Runner) -> None:
    hex_text = encoding.encode_hex(classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE))
    result = run(["decrypt", "--mode", "classic", "--passphrase", "another one", hex_text])
    assert classic.derive_offset("another one") != classic.derive_offset(PASSPHRASE)
    assert result.code in (0, 3)
    assert "Traceback" not in result.err
    if result.code == 0:
        assert result.stdout != TEXT.encode("utf-8") + b"\n"
    else:
        assert_clean_error(result, 3)


def test_classic_decrypt_to_invalid_utf8_is_an_input_error(run: Runner) -> None:
    hex_text = encoding.encode_hex(classic.encrypt(b"\xff\xfe\xfd", PASSPHRASE))
    result = run(decrypt_args("classic", hex_text))
    assert_clean_error(result, 3)
    assert "UTF-8" in result.err


# -------------------------------------------------------------------- missing passphrase


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_no_passphrase_source_is_a_usage_error(run: Runner, command: str, mode: str) -> None:
    assert_clean_error(run([command, "--mode", mode, "00"]), 2)


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
def test_both_passphrase_sources_is_a_usage_error(run: Runner, command: str) -> None:
    result = run([command, "--mode", "classic", "--passphrase", "pw", "--prompt", "00"])
    assert_clean_error(result, 2)


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_empty_passphrase_is_a_usage_error(run: Runner, command: str, mode: str) -> None:
    assert_clean_error(run([command, "--mode", mode, "--passphrase", "", "00"]), 2)


def test_empty_prompted_passphrase_is_a_usage_error(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(getpass, "getpass", lambda prompt="", stream=None: "")
    assert_clean_error(run(["encrypt", "--mode", "classic", "--prompt", TEXT]), 2)


@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_prompt_reads_passphrase_with_getpass(
    run: Runner, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    prompts: list[str] = []

    def fake_getpass(prompt: str = "Password: ", stream: object = None) -> str:
        prompts.append(prompt)
        return PASSPHRASE

    monkeypatch.setattr(getpass, "getpass", fake_getpass)
    encrypted = run(["encrypt", "--mode", mode, "--prompt", TEXT])
    assert encrypted.code == 0
    assert len(prompts) == 1
    assert PASSPHRASE not in encrypted.out
    assert PASSPHRASE not in encrypted.err

    # The prompted passphrase is the one used: --passphrase with the same value decrypts.
    decrypted = run(decrypt_args(mode, encrypted.out.strip()))
    assert decrypted.code == 0
    assert decrypted.stdout == TEXT.encode("utf-8") + b"\n"

    prompted_decrypt = run(["decrypt", "--mode", mode, "--prompt", encrypted.out.strip()])
    assert prompted_decrypt.code == 0
    assert prompted_decrypt.stdout == TEXT.encode("utf-8") + b"\n"
    assert len(prompts) == 2


# ----------------------------------------------------------------- usage and exit codes


def test_no_arguments_opens_the_gui(monkeypatch: pytest.MonkeyPatch) -> None:
    from encryptor.gui import app as gui_app

    calls: list[None] = []

    def fake_gui_main() -> int:
        calls.append(None)
        return 0

    monkeypatch.setattr(gui_app, "main", fake_gui_main)
    assert cli.main([]) == 0
    monkeypatch.setattr(sys, "argv", ["encryptor"])
    assert cli.main() == 0
    assert len(calls) == 2


def test_any_argument_still_runs_the_cli(run: Runner) -> None:
    assert_clean_error(run(["bogus"]), 2)


@pytest.mark.parametrize(
    "argv",
    [
        ["bogus"],
        ["encrypt", "--passphrase", "pw", "hi"],
        ["encrypt", "--mode", "rot13", "--passphrase", "pw", "hi"],
        ["encrypt", "--mode", "classic", "--passphrase", "pw", "hi", "extra"],
        ["encrypt", "--mode", "classic", "--passphrase", "pw", "--no-such-flag", "hi"],
        ["crack", "--plaintext", "a"],
        ["crack", "--ciphertext", "00"],
        ["crack", "--plaintext", "a", "--ciphertext", "00", "--max-offset", "0"],
        ["crack", "--plaintext", "a", "--ciphertext", "00", "--max-offset", "-5"],
        ["crack", "--plaintext", "a", "--ciphertext", "00", "--max-offset", "many"],
    ],
)
def test_usage_errors_return_2(run: Runner, argv: list[str]) -> None:
    assert_clean_error(run(argv), 2)


def test_main_returns_int_and_never_raises_system_exit(run: Runner) -> None:
    for argv in (["--help"], ["encrypt"], encrypt_args("classic", TEXT)):
        result = run(argv)
        assert type(result.code) is int


@pytest.mark.parametrize(
    "argv",
    [["--help"], ["encrypt", "--help"], ["decrypt", "--help"], ["crack", "--help"], ["-h"]],
)
def test_help_returns_0_and_says_not_secure(run: Runner, argv: list[str]) -> None:
    result = run(argv)
    assert result.code == 0
    assert result.err == ""
    text = normalized(result.out)
    assert "usage: encryptor" in text
    assert "NOT secure" in text


def test_top_level_help_lists_commands(run: Runner) -> None:
    text = normalized(run(["--help"]).out)
    for word in ("encrypt", "decrypt", "crack"):
        assert word in text


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
def test_encrypt_decrypt_help_lists_options(run: Runner, command: str) -> None:
    text = normalized(run([command, "--help"]).out)
    for option in ("--mode", "classic", "secure", "--decimal", "--passphrase", "--prompt"):
        assert option in text
    # The --passphrase help warns about shell history and points at --prompt.
    assert "history" in text.lower()


def test_crack_help_lists_options(run: Runner) -> None:
    text = normalized(run(["crack", "--help"]).out)
    for option in ("--max-offset", "--plaintext", "--ciphertext"):
        assert option in text


# ------------------------------------------------------------------------ classic notice


def test_classic_runs_print_notice_on_stderr_only(run: Runner) -> None:
    encrypted = run(encrypt_args("classic", TEXT))
    assert encrypted.code == 0
    assert encrypted.err.count(cli.CLASSIC_NOTICE) == 1
    assert cli.CLASSIC_NOTICE not in encrypted.out
    assert "NOT secure" not in encrypted.out

    decrypted = run(decrypt_args("classic", encrypted.out.strip()))
    assert decrypted.code == 0
    assert decrypted.err.count(cli.CLASSIC_NOTICE) == 1
    assert cli.CLASSIC_NOTICE not in decrypted.out

    decimal = run(encrypt_args("classic", "--decimal", TEXT))
    assert decimal.err.count(cli.CLASSIC_NOTICE) == 1
    assert cli.CLASSIC_NOTICE not in decimal.out


def test_secure_runs_do_not_print_notice(run: Runner) -> None:
    encrypted = run(encrypt_args("secure", TEXT))
    assert encrypted.code == 0
    assert cli.CLASSIC_NOTICE not in encrypted.err
    assert cli.CLASSIC_NOTICE not in encrypted.out
    decrypted = run(decrypt_args("secure", encrypted.out.strip()))
    assert decrypted.code == 0
    assert cli.CLASSIC_NOTICE not in decrypted.err
    assert cli.CLASSIC_NOTICE not in decrypted.out


# -------------------------------------------------------------------------------- crack


def crack_args(plaintext: str, ciphertext_hex: str, *extra: str) -> list[str]:
    return ["crack", "--plaintext", plaintext, "--ciphertext", ciphertext_hex, *extra]


def test_crack_success_prints_three_lines(run: Runner) -> None:
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 777)
    result = run(crack_args(CRACK_MESSAGE, ciphertext.hex(), "--max-offset", "2048"))
    assert result.code == 0
    lines = result.out.splitlines()
    assert len(lines) == 3
    assert lines[0] == "offset: 777"
    assert lines[1] == "candidates tried: 778"
    assert re.fullmatch(r"elapsed: \d+\.\d{3} s", lines[2])
    assert result.err.count(cli.CLASSIC_NOTICE) == 1
    assert cli.CLASSIC_NOTICE not in result.out


def test_crack_default_range_recovers_passphrase_offset(run: Runner) -> None:
    # Default --max-offset is classic.OFFSET_BOUND (patched to 4096 here), read at run time.
    ciphertext = classic.encrypt(CRACK_MESSAGE.encode("utf-8"), PASSPHRASE)
    offset = classic.derive_offset(PASSPHRASE)
    result = run(crack_args(CRACK_MESSAGE, ciphertext.hex().upper()))
    assert result.code == 0
    lines = result.out.splitlines()
    assert lines[0] == f"offset: {offset}"
    assert lines[1] == f"candidates tried: {offset + 1}"


def test_crack_out_of_range_returns_5(run: Runner) -> None:
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 9000)
    result = run(crack_args(CRACK_MESSAGE, ciphertext.hex(), "--max-offset", "4096"))
    assert_clean_error(result, 5)
    pattern = (
        r"encryptor: error: offset not found in \[0, 4096\) "
        r"after 4096 candidates \(\d+\.\d{3} s\)"
    )
    assert any(re.fullmatch(pattern, line) for line in result.err.splitlines())


def test_crack_out_of_default_range_returns_5(run: Runner) -> None:
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 5000)
    result = run(crack_args(CRACK_MESSAGE, ciphertext.hex()))
    assert_clean_error(result, 5)
    assert f"[0, {SMALL_BOUND})" in result.err


@pytest.mark.parametrize(
    ("plaintext", "ciphertext_hex"),
    [
        ("abc", "zz"),
        ("abc", "abc"),
        ("abc", "0011"),
        ("abc", ""),
        ("", ""),
        ("", "001122"),
    ],
)
def test_crack_bad_input_returns_3(run: Runner, plaintext: str, ciphertext_hex: str) -> None:
    assert_clean_error(run(crack_args(plaintext, ciphertext_hex, "--max-offset", "16")), 3)


# ----------------------------------------------------------------------- no secret leak


def test_passphrase_and_offset_are_never_printed(run: Runner) -> None:
    plaintext = "nothing to see here"
    offset_text = str(classic.derive_offset(PASSPHRASE))
    expected_hex = encoding.encode_hex(classic.encrypt(plaintext.encode("utf-8"), PASSPHRASE))
    # Preconditions that make the check meaningful.
    assert len(offset_text) >= 3
    assert offset_text not in expected_hex
    assert offset_text not in cli.CLASSIC_NOTICE

    encrypted = run(encrypt_args("classic", plaintext))
    assert encrypted.code == 0
    for stream in (encrypted.out, encrypted.err):
        assert PASSPHRASE not in stream
        assert offset_text not in stream

    decrypted = run(decrypt_args("classic", expected_hex))
    assert decrypted.code == 0
    assert decrypted.out == plaintext + "\n"
    assert PASSPHRASE not in decrypted.err
    assert offset_text not in decrypted.err


def test_secure_run_does_not_print_passphrase(run: Runner) -> None:
    encrypted = run(encrypt_args("secure", TEXT))
    assert PASSPHRASE not in encrypted.out
    assert PASSPHRASE not in encrypted.err
    decrypted = run(decrypt_args("secure", encrypted.out.strip()))
    assert PASSPHRASE not in decrypted.out
    assert PASSPHRASE not in decrypted.err


def test_error_output_does_not_print_passphrase(run: Runner) -> None:
    for argv in (
        decrypt_args("classic", "zz"),
        decrypt_args("secure", "01"),
        decrypt_args("secure", "--decimal", "00"),
    ):
        result = run(argv)
        assert result.code != 0
        assert PASSPHRASE not in result.err
        assert PASSPHRASE not in result.out


# ---------------------------------------------------------------------- real process run


def run_process(argv: list[str], stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "encryptor.cli", *argv],
        input=stdin,
        capture_output=True,
        timeout=120,
        check=False,
    )


def test_module_entry_point_round_trip_through_real_streams() -> None:
    # Passphrase "b" derives offset 157 under the production bound, so this is fast.
    text = "pipe me é"
    encrypted = run_process(
        ["encrypt", "--mode", "classic", "--passphrase", "b", "-"], stdin=text.encode("utf-8")
    )
    assert encrypted.returncode == 0
    hex_text = encrypted.stdout.decode("ascii").strip()
    assert hex_text == classic.encrypt_at_offset(text.encode("utf-8"), 157).hex()
    assert b"NOT secure" in encrypted.stderr
    assert b"NOT secure" not in encrypted.stdout

    decrypted = run_process(
        ["decrypt", "--mode", "classic", "--passphrase", "b"], stdin=encrypted.stdout
    )
    assert decrypted.returncode == 0
    assert decrypted.stdout.rstrip(b"\r\n") == text.encode("utf-8")
    assert decrypted.stdout != text.encode("utf-8")


def test_module_entry_point_error_exit_codes() -> None:
    bad_hex = run_process(["decrypt", "--mode", "classic", "--passphrase", "b", "zz"])
    assert bad_hex.returncode == 3
    assert bad_hex.stdout == b""
    assert b"encryptor: error:" in bad_hex.stderr
    assert b"Traceback" not in bad_hex.stderr

    usage = run_process(["encrypt", "--mode", "classic", "hi"])
    assert usage.returncode == 2
    assert b"Traceback" not in usage.stderr

    assert run_process(["--help"]).returncode == 0


# ------------------------------------------------------- CLI hardening regressions


class BrokenPipeBuffer(io.BytesIO):
    """A binary stdout whose reader has gone away: writes and flushes raise ``BrokenPipeError``.

    Like any in-memory stream it has no file descriptor (``fileno()`` raises
    ``io.UnsupportedOperation``). ``broken`` is switched off after the call under test so
    that closing the wrapper during garbage collection does not raise again.
    """

    def __init__(self) -> None:
        super().__init__()
        self.broken = True

    def write(self, data: bytes | bytearray | memoryview, /) -> int:  # type: ignore[override]
        if self.broken:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")
        return super().write(data)

    def flush(self) -> None:
        if self.broken:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")
        super().flush()


def run_with_broken_stdout(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> CliResult:
    """Call ``cli.main(argv)`` with a stdout that raises ``BrokenPipeError``; capture stderr."""
    out_raw = BrokenPipeBuffer()
    out = io.TextIOWrapper(out_raw, encoding="utf-8", newline="\n")
    err_raw = io.BytesIO()
    err = io.TextIOWrapper(err_raw, encoding="utf-8", newline="\n")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b""), encoding="utf-8"))
            patch.setattr(sys, "stdout", out)
            patch.setattr(sys, "stderr", err)
            code = cli.main(argv)
            err.flush()
    finally:
        out_raw.broken = False
    assert isinstance(code, int)
    return CliResult(code, b"", err_raw.getvalue())


@pytest.mark.parametrize(
    "argv",
    [
        ["encrypt", "--mode", "secure", "--passphrase", "my", "secret", "zebraword", "quaggaword"],
        ["decrypt", "--mode", "secure", "--passphrase", "my", "secret", "zebraword", "quaggaword"],
        ["encrypt", "--mode", "classic", "--passphrase", "my", "secret", "zebraword", "quaggaword"],
        ["crack", "--plaintext", "a", "--ciphertext", "00", "zebraword", "quaggaword"],
        ["crack", "zebraword", "--plaintext", "a", "--ciphertext", "00", "quaggaword"],
    ],
    ids=["encrypt-secure", "decrypt-secure", "encrypt-classic", "crack-trailing", "crack-mixed"],
)
def test_extra_arguments_are_not_echoed(run: Runner, argv: list[str]) -> None:
    # the trailing words of an unquoted multi-word passphrase must not reach stderr.
    result = run(argv)
    assert_clean_error(result, 2)
    assert "error:" in result.err
    assert "zebraword" not in result.err
    assert "quaggaword" not in result.err


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
@pytest.mark.parametrize("mode", ["classic", "secure"])
def test_prompt_eof_is_a_usage_error(
    run: Runner, monkeypatch: pytest.MonkeyPatch, command: str, mode: str
) -> None:
    # --prompt with no terminal (getpass raises EOFError) is a clean exit 2.
    def no_terminal(prompt: str = "", stream: object = None) -> str:
        raise EOFError

    monkeypatch.setattr(getpass, "getpass", no_terminal)
    try:
        result = run([command, "--mode", mode, "--prompt", "hi"])
    except EOFError:
        pytest.fail("EOFError from getpass escaped cli.main")
    assert_clean_error(result, 2)


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
def test_prompt_keyboard_interrupt_returns_130(
    run: Runner, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    # Ctrl-C at the passphrase prompt is one clean line and the conventional code 130.
    def interrupted(prompt: str = "", stream: object = None) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(getpass, "getpass", interrupted)
    try:
        result = run([command, "--mode", "secure", "--prompt", "hi"])
    except KeyboardInterrupt:
        # Caught here so an unfixed main fails this test instead of aborting the session.
        pytest.fail("KeyboardInterrupt from getpass escaped cli.main")
    assert result.code == 130
    assert result.stdout == b""
    assert "Traceback" not in result.err
    assert "encryptor: error: interrupted" in result.err.splitlines()


def test_broken_pipe_buffer_behaves_like_a_closed_pipe() -> None:
    # Guards the closed-pipe tests against a mistake in the fake itself.
    raw = BrokenPipeBuffer()
    stream = io.TextIOWrapper(raw, encoding="utf-8", newline="\n")
    try:
        stream.write("text")
        with pytest.raises(BrokenPipeError):
            stream.flush()
        with pytest.raises(BrokenPipeError):
            stream.buffer.write(b"raw")
        with pytest.raises(io.UnsupportedOperation):
            stream.fileno()
    finally:
        raw.broken = False


def broken_pipe_argv(case: str) -> list[str]:
    if case == "encrypt-secure":
        return ["encrypt", "--mode", "secure", "--passphrase", "x", "hello"]
    if case == "encrypt-classic":
        return ["encrypt", "--mode", "classic", "--passphrase", "x", "hello"]
    if case == "decrypt-classic":
        hex_text = classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE).hex()
        return decrypt_args("classic", hex_text)
    if case == "decrypt-secure":
        return decrypt_args("secure", secure.encrypt(TEXT.encode("utf-8"), PASSPHRASE).hex())
    if case == "crack":
        ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 5)
        return crack_args(CRACK_MESSAGE, ciphertext.hex(), "--max-offset", "64")
    raise AssertionError(case)


@pytest.mark.parametrize(
    "case",
    ["encrypt-secure", "encrypt-classic", "decrypt-classic", "decrypt-secure", "crack"],
)
def test_broken_pipe_on_stdout_returns_1(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    # the reader of stdout went away (for example `encryptor ... | head -c 0`).
    argv = broken_pipe_argv(case)
    try:
        result = run_with_broken_stdout(monkeypatch, argv)
    except BrokenPipeError:
        pytest.fail("BrokenPipeError from stdout escaped cli.main")
    assert result.code == 1
    assert "Traceback" not in result.err


class OutOfMemoryScrypt:
    """Stands in for the library's ``Scrypt`` when its work area cannot be allocated."""

    def __init__(self, *, salt: bytes, length: int, n: int, r: int, p: int) -> None:
        self.arguments = (salt, length, n, r, p)

    def derive(self, key_material: bytes) -> bytes:
        raise MemoryError("boom")


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
def test_scrypt_memory_error_is_a_clean_error(
    run: Runner, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    # scrypt running out of memory is exit 1 with one clean line, not a traceback.
    monkeypatch.setattr(secure, "Scrypt", OutOfMemoryScrypt)
    data = "hi" if command == "encrypt" else (b"\x01" + bytes(44)).hex()
    try:
        result = run([command, "--mode", "secure", "--passphrase", "p", data])
    except MemoryError:
        pytest.fail("MemoryError from scrypt escaped cli.main")
    assert_clean_error(result, 1)
    assert "memory" in result.err.lower()
    assert "boom" not in result.err


@pytest.mark.parametrize(
    "value",
    ["1_0", " 10 ", " 10", "10 ", "+10", "\u0661\u0660", "\uff11\uff10", "10\n"],
    ids=[
        "underscore",
        "spaces",
        "leading-space",
        "trailing-space",
        "plus",
        "arabic-indic",
        "fullwidth",
        "newline",
    ],
)
def test_max_offset_accepts_ascii_digits_only(run: Runner, value: str) -> None:
    # int() alone accepts these spellings of ten. The offset of the pair (3) is in
    # range, so an unfixed parser returns 0 here.
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 3)
    result = run(crack_args(CRACK_MESSAGE, ciphertext.hex(), "--max-offset", value))
    assert_clean_error(result, 2)


@pytest.mark.parametrize("value", ["10", "4"])
def test_max_offset_plain_digits_are_accepted(run: Runner, value: str) -> None:
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 3)
    result = run(crack_args(CRACK_MESSAGE, ciphertext.hex(), "--max-offset", value))
    assert result.code == 0
    assert result.out.splitlines()[0] == "offset: 3"


# ----------------------------------------------------------- broken stderr regressions

STREAM_ERRNOS = [errno.EPIPE, errno.EINVAL]
STREAM_ERRNO_IDS = ["epipe", "einval"]


class ClosedPipeBuffer(BrokenPipeBuffer):
    """A closed pipe that fails with a chosen errno.

    ``errno.EPIPE`` gives ``BrokenPipeError`` (what POSIX raises); ``errno.EINVAL`` gives
    a plain ``OSError``, which is what a closed pipe raises on Windows.
    """

    def __init__(self, error_number: int) -> None:
        super().__init__()
        self.error_number = error_number

    def _error(self) -> OSError:
        return OSError(self.error_number, "closed pipe")

    def write(self, data: bytes | bytearray | memoryview, /) -> int:  # type: ignore[override]
        if self.broken:
            raise self._error()
        return super().write(data)

    def flush(self) -> None:
        if self.broken:
            raise self._error()
        super().flush()


def run_with_broken_stderr(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    error_number: int,
    *,
    stdout_broken: bool = False,
) -> CliResult:
    """Call ``cli.main(argv)`` with a stderr that fails like a closed pipe.

    stderr is line buffered, as the interpreter's own stderr is, so every printed line
    reaches the failing buffer at once. stdout is a normal in-memory stream unless
    ``stdout_broken``, in which case it fails with ``BrokenPipeError``. The result holds
    what reached a working stdout; a broken stream is reported as empty. An ``OSError``
    that escapes ``main`` fails the test.
    """
    out_raw = BrokenPipeBuffer() if stdout_broken else io.BytesIO()
    err_raw = ClosedPipeBuffer(error_number)
    out = io.TextIOWrapper(out_raw, encoding="utf-8", newline="\n")
    err = io.TextIOWrapper(err_raw, encoding="utf-8", newline="\n", line_buffering=True)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b""), encoding="utf-8"))
            patch.setattr(sys, "stdout", out)
            patch.setattr(sys, "stderr", err)
            try:
                code = cli.main(argv)
            except OSError as error:
                pytest.fail(f"{type(error).__name__} from a closed stream escaped cli.main")
            if not stdout_broken:
                out.flush()
    finally:
        err_raw.broken = False
        if isinstance(out_raw, BrokenPipeBuffer):
            out_raw.broken = False
    assert isinstance(code, int)
    return CliResult(code, b"" if stdout_broken else out_raw.getvalue(), b"")


@pytest.mark.parametrize("error_number", STREAM_ERRNOS, ids=STREAM_ERRNO_IDS)
def test_closed_pipe_buffer_fails_with_the_chosen_errno(error_number: int) -> None:
    # Guards the broken-stderr tests against a mistake in the fake itself.
    raw = ClosedPipeBuffer(error_number)
    stream = io.TextIOWrapper(raw, encoding="utf-8", newline="\n", line_buffering=True)
    try:
        with pytest.raises(OSError) as caught:
            print("a line", file=stream)
        assert caught.value.errno == error_number
        assert isinstance(caught.value, BrokenPipeError) == (error_number == errno.EPIPE)
        with pytest.raises(OSError):
            stream.buffer.flush()
        with pytest.raises(io.UnsupportedOperation):
            stream.fileno()
    finally:
        raw.broken = False


@pytest.mark.parametrize("error_number", STREAM_ERRNOS, ids=STREAM_ERRNO_IDS)
def test_broken_stderr_classic_encrypt_still_succeeds(
    run: Runner, monkeypatch: pytest.MonkeyPatch, error_number: int
) -> None:
    # the classic notice cannot be written; the result must still reach stdout.
    argv = encrypt_args("classic", TEXT)
    expected = run(argv)
    assert expected.code == 0
    assert expected.out == classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE).hex() + "\n"
    result = run_with_broken_stderr(monkeypatch, argv, error_number)
    assert result.code == 0
    assert result.stdout == expected.stdout


@pytest.mark.parametrize("error_number", STREAM_ERRNOS, ids=STREAM_ERRNO_IDS)
def test_broken_stderr_classic_decrypt_still_succeeds(
    monkeypatch: pytest.MonkeyPatch, error_number: int
) -> None:
    hex_text = classic.encrypt(UNICODE_TEXT.encode("utf-8"), PASSPHRASE).hex()
    result = run_with_broken_stderr(monkeypatch, decrypt_args("classic", hex_text), error_number)
    assert result.code == 0
    assert result.stdout == UNICODE_TEXT.encode("utf-8") + b"\n"


@pytest.mark.parametrize("error_number", STREAM_ERRNOS, ids=STREAM_ERRNO_IDS)
def test_broken_stderr_crack_hit_still_prints_three_lines(
    monkeypatch: pytest.MonkeyPatch, error_number: int
) -> None:
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 777)
    argv = crack_args(CRACK_MESSAGE, ciphertext.hex(), "--max-offset", "2048")
    result = run_with_broken_stderr(monkeypatch, argv, error_number)
    assert result.code == 0
    lines = result.out.splitlines()
    assert len(lines) == 3
    assert lines[0] == "offset: 777"
    assert lines[1] == "candidates tried: 778"
    assert re.fullmatch(r"elapsed: \d+\.\d{3} s", lines[2])


def broken_stderr_error_argv(case: str) -> list[str]:
    if case == "wrong-secure-passphrase":
        blob = secure.encrypt(TEXT.encode("utf-8"), PASSPHRASE)
        return ["decrypt", "--mode", "secure", "--passphrase", PASSPHRASE + "x", blob.hex()]
    if case == "bad-hex-classic":  # the notice and the error line both fail to write
        return decrypt_args("classic", "zz")
    if case == "bad-hex-secure":
        return decrypt_args("secure", "zz")
    if case == "crack-miss":
        ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 900)
        return crack_args(CRACK_MESSAGE, ciphertext.hex(), "--max-offset", "64")
    if case == "usage-decimal-secure":
        return encrypt_args("secure", "--decimal", TEXT)
    if case == "usage-no-passphrase":
        return ["encrypt", "--mode", "classic", TEXT]
    raise AssertionError(case)


@pytest.mark.parametrize("error_number", STREAM_ERRNOS, ids=STREAM_ERRNO_IDS)
@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("wrong-secure-passphrase", 4),
        ("bad-hex-classic", 3),
        ("bad-hex-secure", 3),
        ("crack-miss", 5),
        ("usage-decimal-secure", 2),
        ("usage-no-passphrase", 2),
    ],
)
def test_broken_stderr_keeps_the_documented_exit_code(
    run: Runner, monkeypatch: pytest.MonkeyPatch, case: str, code: int, error_number: int
) -> None:
    # an error line that cannot be written must not change the exit code.
    argv = broken_stderr_error_argv(case)
    assert_clean_error(run(argv), code)  # the case itself, with working streams
    result = run_with_broken_stderr(monkeypatch, argv, error_number)
    assert result.code == code
    assert result.stdout == b""


@pytest.mark.parametrize("error_number", STREAM_ERRNOS, ids=STREAM_ERRNO_IDS)
def test_broken_stderr_keyboard_interrupt_still_returns_130(
    monkeypatch: pytest.MonkeyPatch, error_number: int
) -> None:
    # the "interrupted" line is written from an exception handler in main.
    def interrupted(prompt: str = "", stream: object = None) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(getpass, "getpass", interrupted)
    argv = ["encrypt", "--mode", "secure", "--prompt", "hi"]
    try:
        result = run_with_broken_stderr(monkeypatch, argv, error_number)
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt from getpass escaped cli.main")
    assert result.code == 130
    assert result.stdout == b""


@pytest.mark.parametrize("error_number", STREAM_ERRNOS, ids=STREAM_ERRNO_IDS)
@pytest.mark.parametrize(
    "case",
    ["encrypt-secure", "encrypt-classic", "decrypt-classic", "decrypt-secure", "crack"],
)
def test_both_streams_broken_returns_1(
    monkeypatch: pytest.MonkeyPatch, case: str, error_number: int
) -> None:
    # on a success path the closed stdout decides the exit code.
    argv = broken_pipe_argv(case)
    result = run_with_broken_stderr(monkeypatch, argv, error_number, stdout_broken=True)
    assert result.code == 1


def run_process_with_closed_pipe(argv: list[str], stream: str) -> tuple[int, bytes]:
    """Run the CLI with the read end of one output pipe closed before the child writes.

    Returns the exit code and what the child wrote to the other stream. The read end is
    closed straight after the spawn, before the child's interpreter has started; the
    callers also use secure mode, whose key derivation runs before any output.
    """
    process = subprocess.Popen(
        [sys.executable, "-m", "encryptor.cli", *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    closed, kept = (
        (process.stdout, process.stderr) if stream == "stdout" else (process.stderr, process.stdout)
    )
    closed.close()
    try:
        other = kept.read()
        code = process.wait(timeout=120)
    finally:
        kept.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    return code, other


def test_real_closed_stdout_pipe_exits_1_without_traceback() -> None:
    # Closed stdout on real pipes, which covers the Windows EINVAL branch of the handler.
    code, stderr = run_process_with_closed_pipe(
        ["encrypt", "--mode", "secure", "--passphrase", "x", "hello"], "stdout"
    )
    assert code == 1
    assert b"Traceback" not in stderr
    assert b"Exception ignored" not in stderr


def test_real_closed_stderr_pipe_keeps_the_exit_code() -> None:
    # Closed stderr on real pipes. Any well-formed blob fails authentication in the child.
    blob = secure.encrypt(TEXT.encode("utf-8"), PASSPHRASE)
    code, stdout = run_process_with_closed_pipe(
        ["decrypt", "--mode", "secure", "--passphrase", "not the passphrase", blob.hex()],
        "stderr",
    )
    assert code == 4
    assert stdout == b""
