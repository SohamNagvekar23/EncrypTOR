"""Benchmark classic mode, secure mode and CLI startup.

Run as ``python benchmarks/bench_modes.py`` (add ``--quick`` for a reduced set).
Prints Markdown tables:

1. classic encrypt and decrypt end to end (real pi keystream) with peak memory;
2. the classic cipher layer alone, with a synthetic keystream, to show that the
   XOR and chaining work is linear in the input and what memory each API needs;
3. secure encrypt and decrypt with the production scrypt constants;
4. CLI startup time and which heavy modules a classic run imports.

Peak memory is measured with ``tracemalloc`` in a separate, untimed run. It counts
Python allocations only: scrypt's work area lives inside OpenSSL and shows up in the
process peak RSS column instead.
"""

from __future__ import annotations

import os
import statistics
import subprocess
import sys
import time
from collections.abc import Iterator
from functools import partial
from importlib import metadata

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from _common import (
    build_parser,
    cpu_seconds,
    measure,
    peak_rss,
    prefer_full_speed,
    print_header,
    print_speed_check,
    rate,
    seconds,
    size,
    table,
    traced_peak,
)
from encryptor import classic, pi_stream, secure

KIB = 1024
MIB = 1024 * 1024
CLASSIC_SIZES = (16, 256, 4 * KIB)
CLASSIC_OFFSETS = (0, 1 << 16, (1 << 17) - 1)
QUICK_CLASSIC_SIZES = (16, 256)
QUICK_CLASSIC_OFFSETS = (0, 1 << 14)
LAYER_SIZES = (64 * KIB, MIB, 16 * MIB)
QUICK_LAYER_SIZES = (64 * KIB, MIB)
SECURE_SIZES = (16, MIB, 64 * MIB)
QUICK_SECURE_SIZES = (16, MIB)
CHUNK = 64 * KIB
PASSPHRASE = "benchmark passphrase"
STARTUP_RUNS = 15
QUICK_STARTUP_RUNS = 5
# Modules a classic-mode run or --help should not have to import.
WATCHED_MODULES = (
    "cryptography",
    "getpass",
    "encryptor.secure",
    "encryptor.classic",
    "encryptor.crack",
    "dataclasses",
    "hashlib",
)


def bench_classic(sizes: tuple[int, ...], offsets: tuple[int, ...], quick: bool) -> None:
    """Classic mode end to end: the real keystream dominates."""
    print("### Classic mode, end to end (real pi keystream)")
    print()
    rows: list[list[str]] = []
    for offset in offsets:
        for length in sizes:
            plaintext = os.urandom(length)
            ciphertext = classic.encrypt_at_offset(plaintext, offset)
            for name, function, data in (
                ("encrypt", classic.encrypt_at_offset, plaintext),
                ("decrypt", classic.decrypt_at_offset, ciphertext),
            ):
                timing = measure(partial(function, data, offset), quick)
                peak, _ = traced_peak(partial(function, data, offset))
                rows.append(
                    [
                        str(offset),
                        size(length),
                        name,
                        seconds(timing.best),
                        seconds(timing.median),
                        cpu_seconds(timing),
                        rate(length, timing.best, "B/s"),
                        size(peak),
                    ]
                )
    table(
        ("offset", "size", "operation", "min", "median", "CPU min", "rate (min)", "traced peak"),
        rows,
    )


def synthetic_blocks(
    offset: int, length: int | None = None, *, block_digits: int | None = None
) -> Iterator[bytes]:
    """Stand-in for ``pi_stream.keystream_blocks`` that costs nothing per block.

    Yields the same object again and again, the size of a real default block
    (``KEYSTREAM_BLOCK_DIGITS / 2`` bytes), so the timings and memory of the cipher
    layer are not hidden behind BBP.
    """
    del offset, block_digits
    width = pi_stream.KEYSTREAM_BLOCK_DIGITS // 2
    block = bytes(index & 0xFF for index in range(width))
    if length is None:
        while True:
            yield block
    remaining = length
    while remaining > 0:
        yield block if remaining >= width else block[:remaining]
        remaining -= width


def repeated_chunks(chunk: bytes, count: int) -> Iterator[bytes]:
    """Yield the same chunk ``count`` times: a large input that occupies no memory."""
    for _ in range(count):
        yield chunk


def drain(pieces: Iterator[bytes]) -> int:
    """Consume a stream of output pieces without keeping them."""
    return sum(len(piece) for piece in pieces)


def bench_cipher_layer(sizes: tuple[int, ...], quick: bool) -> None:
    """The XOR and chaining layer alone: linear time, and memory of each API."""
    print("### Classic cipher layer alone (synthetic keystream, no BBP)")
    print()
    print(
        "One-shot rows keep the output, so their peak includes it; chunk rows read "
        f"{size(CHUNK)} chunks lazily and discard the output, so their peak is the "
        "extra memory of the cipher itself. Synthetic key blocks are "
        f"{size(pi_stream.KEYSTREAM_BLOCK_DIGITS // 2)}, the default block size."
    )
    print()
    chunk = os.urandom(CHUNK)
    real_blocks = classic.keystream_blocks
    classic.keystream_blocks = synthetic_blocks
    rows: list[list[str]] = []
    try:
        for length in sizes:
            data = os.urandom(length)
            count = length // CHUNK
            cases = (
                ("`encrypt_at_offset`", partial(classic.encrypt_at_offset, data, 0)),
                ("`decrypt_at_offset`", partial(classic.decrypt_at_offset, data, 0)),
                (
                    "`encrypt_chunks`",
                    lambda n=count: drain(classic.encrypt_chunks(repeated_chunks(chunk, n), 0)),
                ),
                (
                    "`decrypt_chunks`",
                    lambda n=count: drain(classic.decrypt_chunks(repeated_chunks(chunk, n), 0)),
                ),
            )
            for name, function in cases:
                timing = measure(function, quick)
                peak, produced = traced_peak(function)
                rows.append(
                    [
                        size(length),
                        name,
                        seconds(timing.best),
                        seconds(timing.median),
                        f"{timing.best / length * 1e9:.1f} ns/B",
                        rate(length / MIB, timing.best, "MiB/s"),
                        size(peak),
                        f"{peak / produced:.2f}" if produced else "-",
                    ]
                )
    finally:
        classic.keystream_blocks = real_blocks
    table(
        (
            "size",
            "API",
            "min",
            "median",
            "time per byte",
            "rate (min)",
            "traced peak",
            "peak / output",
        ),
        rows,
    )


def scrypt_only() -> bytes:
    """One key derivation with the production parameters."""
    kdf = Scrypt(
        salt=bytes(secure.SALT_LEN),
        length=secure.KEY_LEN,
        n=secure.SCRYPT_N,
        r=secure.SCRYPT_R,
        p=secure.SCRYPT_P,
    )
    return kdf.derive(PASSPHRASE.encode())


def bench_secure(sizes: tuple[int, ...], quick: bool) -> None:
    """Secure mode with the production scrypt constants."""
    print("### Secure mode (ChaCha20-Poly1305, scrypt)")
    print()
    print(
        f"scrypt parameters: N = 2^{secure.SCRYPT_N.bit_length() - 1}, r = {secure.SCRYPT_R}, "
        f"p = {secure.SCRYPT_P} ({size(128 * secure.SCRYPT_N * secure.SCRYPT_R)} work area "
        "inside OpenSSL, invisible to tracemalloc)."
    )
    print()
    rows: list[list[str]] = []

    def rss() -> str:
        peak = peak_rss()
        return size(peak) if peak is not None else "n/a"

    before = rss()
    kdf = measure(scrypt_only, quick)
    kdf_peak, _ = traced_peak(scrypt_only)
    rows.append(
        [
            "-",
            "scrypt alone",
            seconds(kdf.best),
            seconds(kdf.median),
            "-",
            size(kdf_peak),
            "-",
            f"{before} -> {rss()}",
        ]
    )
    aead = ChaCha20Poly1305(bytes(secure.KEY_LEN))
    nonce = bytes(secure.NONCE_LEN)
    header = bytes(secure.HEADER_LEN)
    for length in sizes:
        plaintext = os.urandom(length)
        blob = secure.encrypt(plaintext, PASSPHRASE)
        cases = (
            ("encrypt", partial(secure.encrypt, plaintext, PASSPHRASE)),
            ("decrypt", partial(secure.decrypt, blob, PASSPHRASE)),
            (
                "AEAD alone (library call, no scrypt)",
                partial(aead.encrypt, nonce, plaintext, header),
            ),
        )
        for name, function in cases:
            timing = measure(function, quick)
            peak, produced = traced_peak(function)
            rows.append(
                [
                    size(length),
                    name,
                    seconds(timing.best),
                    seconds(timing.median),
                    rate(length / MIB, timing.best, "MiB/s") if length >= MIB else "-",
                    size(peak),
                    f"{peak / produced:.2f}",
                    rss(),
                ]
            )
        del plaintext, blob, cases
    table(
        (
            "size",
            "operation",
            "min",
            "median",
            "rate (min, whole call)",
            "traced peak",
            "peak / output",
            "process peak RSS so far",
        ),
        rows,
    )


def run_cli(arguments: list[str], interpreter_flags: tuple[str, ...] = ()) -> str:
    """Run a Python child process and return its stderr."""
    completed = subprocess.run(
        [sys.executable, *interpreter_flags, *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stderr


def imported_modules(arguments: list[str]) -> tuple[set[str], float]:
    """Return the modules a child process imports and their total import seconds.

    Both come from ``-X importtime``: the names, and the sum of the self-time column.
    """
    names: set[str] = set()
    total_us = 0
    for line in run_cli(arguments, ("-X", "importtime")).splitlines():
        if line.startswith("import time:") and "|" in line:
            fields = line[len("import time:") :].split("|")
            names.add(fields[-1].strip())
            if fields[0].strip().isdigit():
                total_us += int(fields[0])
    return names, total_us / 1e6


def bench_startup(runs: int) -> None:
    """Process start to exit for --help and a tiny classic encryption."""
    print("### CLI startup (whole process, wall time)")
    print()
    cli = ["-m", "encryptor.cli"]
    # The passphrase "b" derives offset 157, so the cipher itself costs well under 1 ms.
    cases = (
        ("`python -c pass` (interpreter only)", ["-c", "pass"]),
        ("`encryptor --help`", [*cli, "--help"]),
        (
            "`encryptor encrypt --mode classic` (tiny offset)",
            [*cli, "encrypt", "--mode", "classic", "--passphrase", "b", "hi"],
        ),
    )
    rows: list[list[str]] = []
    for name, arguments in cases:
        walls: list[float] = []
        for _ in range(runs):
            started = time.perf_counter()
            run_cli(arguments)
            walls.append(time.perf_counter() - started)
        modules: set[str] = set()
        import_times: list[float] = []
        for _ in range(runs):
            modules, import_seconds = imported_modules(arguments)
            import_times.append(import_seconds)
        loaded = [
            watched
            for watched in WATCHED_MODULES
            if any(module == watched or module.startswith(watched + ".") for module in modules)
        ]
        rows.append(
            [
                name,
                seconds(min(walls)),
                seconds(statistics.median(walls)),
                seconds(min(import_times)),
                seconds(statistics.median(import_times)),
                str(len(modules)),
                ", ".join(loaded) or "none",
            ]
        )
    table(
        (
            "command",
            "min",
            "median",
            "import time (min)",
            "import time (median)",
            "modules imported",
            "watched modules imported",
        ),
        rows,
    )
    print(
        "Process start-up is the noisiest measurement here (it depends on the file cache and "
        "on how the OS schedules a new background process); compare the import lists first."
    )
    print()
    print(f"Watched modules: {', '.join(WATCHED_MODULES)}.")
    print()


def main() -> None:
    """Run the mode benchmarks and print the tables."""
    args = build_parser(__doc__ or "").parse_args()
    mode = prefer_full_speed(not args.no_qos)
    print_header("bench_modes", mode, args.quick)
    print(f"`cryptography` {metadata.version('cryptography')}.")
    print()
    quick: bool = args.quick
    bench_classic(
        QUICK_CLASSIC_SIZES if quick else CLASSIC_SIZES,
        QUICK_CLASSIC_OFFSETS if quick else CLASSIC_OFFSETS,
        quick,
    )
    bench_cipher_layer(QUICK_LAYER_SIZES if quick else LAYER_SIZES, quick)
    bench_secure(QUICK_SECURE_SIZES if quick else SECURE_SIZES, quick)
    bench_startup(QUICK_STARTUP_RUNS if quick else STARTUP_RUNS)
    print_speed_check("end")


if __name__ == "__main__":
    main()
