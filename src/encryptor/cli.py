"""Command-line front end: ``encryptor encrypt | decrypt | crack``.

Run with no arguments, ``encryptor`` opens the desktop GUI instead.

Results go to stdout; the classic-mode notice, errors and usage messages go to stderr,
so stdout stays pipeable. Passphrases and derived offsets are never printed (the
``crack`` command prints the offset it recovers, which is its purpose).

The cipher modules (``classic``, ``secure``, ``crack``) are imported only by the
command that needs them, to keep start-up short.
"""

from __future__ import annotations

import argparse
import errno
import os
import sys
from collections.abc import Sequence
from typing import Final, TextIO

from encryptor import (
    AuthenticationError,
    EncryptorError,
    InputFormatError,
    MalformedCiphertextError,
    OffsetNotFoundError,
    encoding,
)

CLASSIC_NOTICE: Final[str] = (
    "WARNING: classic mode is an educational cipher and is NOT secure. "
    "Use --mode secure for real data."
)
EXIT_OK: Final[int] = 0
EXIT_ERROR: Final[int] = 1
EXIT_USAGE: Final[int] = 2
EXIT_INPUT: Final[int] = 3
EXIT_AUTH: Final[int] = 4
EXIT_NOT_FOUND: Final[int] = 5
EXIT_INTERRUPTED: Final[int] = 130

_MODE_HELP: Final[str] = (
    "classic: educational pi-digit running-key cipher, NOT secure; "
    "secure: ChaCha20-Poly1305 with a scrypt-derived key"
)
_PASSPHRASE_HELP: Final[str] = (
    "passphrase given on the command line (visible in shell history and process "
    "lists; prefer --prompt). A passphrase that contains spaces must be quoted, "
    "otherwise the extra word is taken as the input"
)


class _StdoutClosedError(Exception):
    """Standard output is a closed pipe; ``main`` turns this into exit code 1."""


def _write_stdout(*parts: str | bytes) -> None:
    """Write ``parts`` to stdout (text or raw bytes) and flush; no parts only flushes.

    A closed pipe raises ``_StdoutClosedError``: that is ``BrokenPipeError`` on POSIX
    and ``OSError`` with errno ``EINVAL`` on Windows. Any other ``OSError`` propagates.
    Time O(total length), no copy of the parts.
    """
    stdout = sys.stdout
    try:
        for part in parts:
            if isinstance(part, str):
                stdout.write(part)
            else:
                stdout.flush()
                stdout.buffer.write(part)
        stdout.flush()
    except OSError as error:
        if isinstance(error, BrokenPipeError) or (os.name == "nt" and error.errno == errno.EINVAL):
            raise _StdoutClosedError from None
        raise


def _write_stderr(line: str = "") -> None:
    """Best-effort: write ``line`` to stderr (nothing if empty) and flush.

    A stderr that cannot be written (closed pipe, on any platform) must not change
    the exit code, so ``OSError`` is swallowed and the descriptor is discarded.
    """
    stderr = sys.stderr
    try:
        if line:
            stderr.write(line + "\n")
        stderr.flush()
    except OSError:
        _discard(stderr)


def _discard(stream: TextIO) -> None:
    """Point the stream's file descriptor at the null device after a broken pipe.

    Without this the interpreter's flush at exit would fail again (a traceback for
    stdout, exit code 120 for stderr). A stream with no real descriptor is left alone.
    """
    try:
        descriptor = stream.fileno()
    except (OSError, ValueError):  # includes io.UnsupportedOperation
        return
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, descriptor)
        finally:
            os.close(devnull)
    except OSError:
        pass


def _positive_int(text: str) -> int:
    """argparse type for ``--max-offset``: an integer >= 1 written as ASCII digits only.

    Signs, spaces, underscores, newlines and non-ASCII digits are rejected (``int``
    alone would accept them). The bad value is never echoed. Time O(len(text)).
    """
    if not (text.isascii() and text.isdigit()):
        raise argparse.ArgumentTypeError("must be a positive integer")
    try:
        value = int(text)
    except ValueError:  # longer than the interpreter's int-conversion digit limit
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _add_cipher_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    summary: str,
    metavar: str,
    input_help: str,
    decimal_help: str,
) -> None:
    parser = subparsers.add_parser(name, help=summary, description=f"{summary} {CLASSIC_NOTICE}")
    parser.add_argument("--mode", required=True, choices=("classic", "secure"), help=_MODE_HELP)
    parser.add_argument("--decimal", action="store_true", help=decimal_help)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--passphrase", metavar="P", help=_PASSPHRASE_HELP)
    source.add_argument(
        "--prompt", action="store_true", help="read the passphrase from the terminal without echo"
    )
    parser.add_argument("input", nargs="?", default="-", metavar=metavar, help=input_help)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser. Time and space O(1)."""
    parser = argparse.ArgumentParser(
        prog="encryptor",
        description=(
            "Encryption toolkit with two modes and a cryptanalysis demo. "
            "secure mode is ChaCha20-Poly1305 with a scrypt-derived key. " + CLASSIC_NOTICE
        ),
        epilog="Run encryptor with no arguments to open the desktop GUI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    _add_cipher_command(
        subparsers,
        "encrypt",
        "Encrypt text and print the result as hex.",
        "TEXT",
        "text to encrypt; '-' or omitted reads standard input (taken exactly, as UTF-8)",
        "classic mode only: print space-separated decimal byte values instead of hex",
    )
    _add_cipher_command(
        subparsers,
        "decrypt",
        "Decrypt hex produced by 'encrypt' and print the text.",
        "HEX",
        "ciphertext as hex (or decimal with --decimal); '-' or omitted reads standard input",
        "classic mode only: the input is space-separated decimal byte values instead of hex",
    )
    crack_parser = subparsers.add_parser(
        "crack",
        help="Recover a classic-mode offset from a known plaintext/ciphertext pair.",
        description=(
            "Demonstrate why classic mode is NOT secure: recover its secret offset from "
            "one known plaintext/ciphertext pair by searching the hex digits of pi. "
            "Prints the offset, the number of candidates tried and the time taken."
        ),
    )
    crack_parser.add_argument(
        "--max-offset",
        type=_positive_int,
        default=None,
        metavar="N",
        help="search offsets 0 to N-1 (default: the full classic offset range, 2**17)",
    )
    crack_parser.add_argument("--plaintext", required=True, metavar="TEXT", help="known plaintext")
    crack_parser.add_argument(
        "--ciphertext", required=True, metavar="HEX", help="its classic-mode ciphertext as hex"
    )
    return parser


def _utf8(text: str, what: str) -> bytes:
    """Encode a command-line string as UTF-8, reporting undecodable arguments cleanly."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise InputFormatError(f"{what} is not valid Unicode text") from None


def _read_passphrase(parser: argparse.ArgumentParser, args: argparse.Namespace) -> str:
    if args.prompt:
        import getpass

        try:
            passphrase = getpass.getpass("Passphrase: ")
        except EOFError:
            parser.error(
                "no passphrase could be read from the terminal "
                "(--prompt needs an interactive terminal)"
            )
    else:
        passphrase = args.passphrase
    if not passphrase:
        parser.error("the passphrase must not be empty")
    _utf8(passphrase, "passphrase")
    return str(passphrase)


def _read_plaintext(source: str) -> bytes:
    """Return the bytes to encrypt: the argument as UTF-8, or stdin taken exactly."""
    if source != "-":
        return _utf8(source, "TEXT")
    data = sys.stdin.buffer.read()
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputFormatError("input is not valid UTF-8 text") from None
    return data


def _read_ciphertext(source: str, decimal: bool) -> bytes:
    """Return the ciphertext bytes parsed from the argument or stdin."""
    if source == "-":
        try:
            source = sys.stdin.buffer.read().decode("ascii")
        except UnicodeDecodeError:
            raise InputFormatError("input is not ASCII text") from None
    return encoding.decode_decimal(source) if decimal else encoding.decode_hex(source)


def _run_cipher(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    is_classic = args.mode == "classic"
    if args.decimal and not is_classic:
        parser.error("--decimal is only available with --mode classic")
    passphrase = _read_passphrase(parser, args)
    if is_classic:
        _write_stderr(CLASSIC_NOTICE)

    if args.command == "encrypt":
        plaintext = _read_plaintext(args.input)
        if is_classic:
            from encryptor import classic

            ciphertext = classic.encrypt(plaintext, passphrase)
        else:
            from encryptor import secure

            ciphertext = secure.encrypt(plaintext, passphrase)
        encode = encoding.encode_decimal if args.decimal else encoding.encode_hex
        _write_stdout(encode(ciphertext), "\n")
        return EXIT_OK

    ciphertext = _read_ciphertext(args.input, args.decimal)
    if is_classic:
        from encryptor import classic

        plaintext = classic.decrypt(ciphertext, passphrase)
        try:
            plaintext.decode("utf-8")
        except UnicodeDecodeError:
            raise InputFormatError(
                "decrypted data is not valid UTF-8 (wrong passphrase or corrupted ciphertext)"
            ) from None
    else:
        from encryptor import secure

        plaintext = secure.decrypt(ciphertext, passphrase)
    _write_stdout(plaintext, b"\n")
    return EXIT_OK


def _run_crack(args: argparse.Namespace) -> int:
    from encryptor import crack

    _write_stderr(CLASSIC_NOTICE)
    plaintext = _utf8(args.plaintext, "--plaintext")
    ciphertext = encoding.decode_hex(args.ciphertext)
    result = crack.crack(plaintext, ciphertext, args.max_offset)
    _write_stdout(
        f"offset: {result.offset}\n"
        f"candidates tried: {result.candidates_tried}\n"
        f"elapsed: {result.elapsed_seconds:.3f} s\n"
    )
    return EXIT_OK


def _exit_code_for(error: EncryptorError) -> int:
    if isinstance(error, InputFormatError | MalformedCiphertextError):
        return EXIT_INPUT
    if isinstance(error, AuthenticationError):
        return EXIT_AUTH
    if isinstance(error, OffsetNotFoundError):
        return EXIT_NOT_FOUND
    return EXIT_ERROR


def _run(argv: Sequence[str] | None) -> int:
    """Parse ``argv`` and run the chosen command; see ``main`` for the error mapping."""
    parser = build_parser()
    try:
        args, extras = parser.parse_known_args(argv)
        if extras:
            # The extras are not listed: they may be the tail of an unquoted passphrase.
            parser.error(
                "unexpected extra arguments "
                "(put quotes around a passphrase or text that contains spaces)"
            )
        if args.command == "crack":
            return _run_crack(args)
        return _run_cipher(parser, args)
    except SystemExit as exit_request:
        code = exit_request.code
        if code is None or code == 0:
            # argparse printed --help without flushing; flush here so that a closed
            # pipe is reported by main and not at interpreter exit.
            _write_stdout()
            return EXIT_OK
        # argparse swallows a failed write of its usage error; flush here so that a
        # closed stderr is discarded and cannot change the exit code at exit.
        _write_stderr()
        return code if isinstance(code, int) else EXIT_ERROR
    except EncryptorError as error:
        _write_stderr(f"encryptor: error: {error}")
        return _exit_code_for(error)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code.

    Never raises for expected failures: argparse exits are converted to their code
    (2 for usage errors, 0 for ``--help``), every ``EncryptorError`` becomes one
    ``encryptor: error: ...`` line on stderr with a mapped exit code, Ctrl-C gives
    ``encryptor: error: interrupted`` and 130, and a closed stdout pipe gives 1
    without a traceback. Writes to stderr are best-effort: a closed stderr never
    changes the exit code. With no arguments at all it opens the desktop GUI and
    returns its exit code (the GUI is imported only then, so start-up stays short).
    """
    try:
        if not (sys.argv[1:] if argv is None else argv):
            from encryptor.gui.app import main as gui_main

            return gui_main()
        return _run(argv)
    except KeyboardInterrupt:
        _write_stderr("encryptor: error: interrupted")
        return EXIT_INTERRUPTED
    except _StdoutClosedError:
        _discard(sys.stdout)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
