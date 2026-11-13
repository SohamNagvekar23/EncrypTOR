"""Benchmark the BBP digit functions and the pi keystream.

Run as ``python benchmarks/bench_pi_stream.py`` (add ``--quick`` for a reduced set).
Prints Markdown tables:

1. one evaluation of ``pi_hex_digit`` against ``pi_hex_int`` for several widths;
2. the number of BBP evaluations the keystream issues (must be one per block);
3. keystream throughput for several block widths.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial

from _common import (
    build_parser,
    cpu_seconds,
    measure,
    prefer_full_speed,
    print_header,
    print_speed_check,
    rate,
    seconds,
    table,
)
from encryptor import pi_stream

POSITIONS = (0, 1 << 10, 1 << 14, 1 << 16, (1 << 17) - 1)
COUNTS = (1, 8, 64, 512, 4096)
BLOCK_DIGITS = (8, 64, 512, 2048, 4096, 8192, 16384)
QUICK_POSITIONS = (0, 1 << 10, 1 << 14)
QUICK_COUNTS = (1, 8, 512)
QUICK_BLOCK_DIGITS = (8, 512, 4096)
# (offset, message bytes, block digits) for the evaluation-count check.
COUNT_CASES = (
    (1000, 4, 8),
    (1000, 100, 8),
    (1000, 100, 64),
    (1000, 256, 512),
    (1000, 257, 512),
    (1001, 1000, 512),
    (1000, 1000, None),
    (1000, 2048, None),
    (1000, 2049, None),
    (1001, 5000, None),
)


def bench_evaluations(positions: tuple[int, ...], counts: tuple[int, ...], quick: bool) -> None:
    """Time single evaluations; show that a batch costs about one single digit."""
    print("### One BBP evaluation")
    print()
    rows: list[list[str]] = []
    for position in positions:
        single = measure(partial(pi_stream.pi_hex_digit, position), quick)
        rows.append(
            [
                str(position),
                "`pi_hex_digit`",
                "1",
                seconds(single.best),
                seconds(single.median),
                cpu_seconds(single),
                rate(1, single.best, "digits/s"),
                "1.00",
            ]
        )
        for count in counts:
            batch = measure(partial(pi_stream.pi_hex_int, position, count), quick)
            rows.append(
                [
                    str(position),
                    "`pi_hex_int`",
                    str(count),
                    seconds(batch.best),
                    seconds(batch.median),
                    cpu_seconds(batch),
                    rate(count, batch.best, "digits/s"),
                    f"{batch.best / single.best:.2f}",
                ]
            )
    table(
        (
            "position",
            "function",
            "digits",
            "min",
            "median",
            "CPU min",
            "digits/s (min)",
            "time vs `pi_hex_digit`",
        ),
        rows,
    )


def count_evaluations(function: Callable[[], object]) -> int:
    """Run ``function`` and return how many times it called ``pi_stream.pi_hex_int``."""
    original = pi_stream.pi_hex_int
    calls = 0

    def counting(position: int, count: int = 8, *, guard_bits: int | None = None) -> int:
        nonlocal calls
        calls += 1
        return original(position, count, guard_bits=guard_bits)

    pi_stream.pi_hex_int = counting
    try:
        function()
    finally:
        pi_stream.pi_hex_int = original
    return calls


def bench_batching() -> None:
    """Count BBP evaluations per keystream request."""
    print("### BBP evaluations issued by the keystream")
    print()
    rows: list[list[str]] = []
    for offset, length, block in COUNT_CASES:
        digits = pi_stream.KEYSTREAM_BLOCK_DIGITS if block is None else block
        expected = -(-2 * length // digits)

        def consume(o: int = offset, n: int = length, b: int | None = block) -> int:
            return sum(len(piece) for piece in pi_stream.keystream_blocks(o, n, block_digits=b))

        calls = count_evaluations(consume)
        rows.append(
            [
                str(offset),
                str(length),
                f"default ({digits})" if block is None else str(block),
                str(calls),
                str(expected),
                "yes" if calls == expected else "NO",
                f"{2 * length / calls:.1f}",
            ]
        )
    table(
        (
            "offset",
            "bytes",
            "block digits",
            "evaluations",
            "ceil(2n / block)",
            "one per block",
            "digits per evaluation",
        ),
        rows,
    )


def bench_keystream(positions: tuple[int, ...], blocks: tuple[int, ...], quick: bool) -> None:
    """Keystream throughput: bytes per second for each block width."""
    print("### Keystream throughput (bytes per second, best run; median in brackets)")
    print()
    rows: list[list[str]] = []
    for offset in positions:
        row = [str(offset)]
        for block in blocks:
            # Small blocks are cheap per call, so time a few of them.
            pieces = 4 if block < 512 else 1
            length = pieces * block // 2

            def consume(o: int = offset, n: int = length, b: int = block) -> int:
                return sum(len(piece) for piece in pi_stream.keystream_blocks(o, n, block_digits=b))

            timing = measure(consume, quick)
            row.append(f"{rate(length, timing.best, 'B/s')} ({rate(length, timing.median, 'B/s')})")
        rows.append(row)
    default = pi_stream.KEYSTREAM_BLOCK_DIGITS
    table(
        (
            "offset",
            *(f"block {block}" + (" (default)" if block == default else "") for block in blocks),
        ),
        rows,
    )


def main() -> None:
    """Run the pi_stream benchmarks and print the tables."""
    args = build_parser(__doc__ or "").parse_args()
    mode = prefer_full_speed(not args.no_qos)
    print_header("bench_pi_stream", mode, args.quick)
    positions = QUICK_POSITIONS if args.quick else POSITIONS
    bench_evaluations(positions, QUICK_COUNTS if args.quick else COUNTS, args.quick)
    bench_batching()
    bench_keystream(positions, QUICK_BLOCK_DIGITS if args.quick else BLOCK_DIGITS, args.quick)
    print(f"Current `KEYSTREAM_BLOCK_DIGITS`: {pi_stream.KEYSTREAM_BLOCK_DIGITS}.")
    print_speed_check("end")


if __name__ == "__main__":
    main()
