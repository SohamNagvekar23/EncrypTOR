"""Benchmark the known-plaintext crack demo for classic mode.

Run as ``python benchmarks/bench_crack.py`` (add ``--quick`` for a reduced set).
Prints one Markdown table: wall time and peak ``tracemalloc`` memory of ``crack`` for
several true offsets and for a miss over the whole searched range. Memory is measured
in a separate, untimed run because ``tracemalloc`` slows big-integer code down.
"""

from __future__ import annotations

from functools import partial

from _common import (
    build_parser,
    cpu_seconds,
    measure,
    prefer_full_speed,
    print_header,
    print_speed_check,
    seconds,
    size,
    table,
    traced_peak,
)
from encryptor import OffsetNotFoundError, classic
from encryptor import crack as crack_module

PLAINTEXT = b"known plaintext for the crack demo"
HIT_OFFSETS = (1 << 10, 1 << 14, 1 << 16, (1 << 17) - 1)
QUICK_HIT_OFFSETS = (1 << 10, 1 << 14)
QUICK_MISS_RANGE = 1 << 14


def expect_hit(ciphertext: bytes, offset: int) -> None:
    """Run the search and check that it recovers ``offset``."""
    result = crack_module.crack(PLAINTEXT, ciphertext)
    if result.offset != offset:
        raise AssertionError(f"crack returned {result.offset}, expected {offset}")


def expect_miss(ciphertext: bytes, limit: int) -> None:
    """Run the search over ``[0, limit)`` and check that it reports a clean miss."""
    try:
        crack_module.crack(PLAINTEXT, ciphertext, limit)
    except OffsetNotFoundError as error:
        if error.candidates_tried != limit:
            raise AssertionError("wrong candidate count on a miss") from None
        return
    raise AssertionError("crack found an offset that is outside the searched range")


def main() -> None:
    """Run the crack benchmarks and print the table."""
    args = build_parser(__doc__ or "").parse_args()
    mode = prefer_full_speed(not args.no_qos)
    print_header("bench_crack", mode, args.quick)
    quick: bool = args.quick
    offsets = QUICK_HIT_OFFSETS if quick else HIT_OFFSETS
    miss_range = QUICK_MISS_RANGE if quick else classic.OFFSET_BOUND

    cases = [
        (
            f"hit at offset {offset}",
            offset + 1,
            partial(expect_hit, classic.encrypt_at_offset(PLAINTEXT, offset), offset),
        )
        for offset in offsets
    ]
    # A pair made just outside the range can never be found inside it.
    outside = classic.encrypt_at_offset(PLAINTEXT, miss_range + 1000)
    cases.append(
        (f"miss over [0, {miss_range})", miss_range, partial(expect_miss, outside, miss_range))
    )

    print(
        f"Message: {len(PLAINTEXT)} bytes. `CRACK_CHUNK_DIGITS` = "
        f"{crack_module.CRACK_CHUNK_DIGITS}, `CRACK_PREFIX_BYTES` = "
        f"{crack_module.CRACK_PREFIX_BYTES}."
    )
    print()
    rows: list[list[str]] = []
    for name, candidates, function in cases:
        timing = measure(function, quick)
        peak, _ = traced_peak(function)
        rows.append(
            [
                name,
                str(candidates),
                seconds(timing.best),
                seconds(timing.median),
                cpu_seconds(timing),
                str(timing.runs),
                f"{candidates / timing.best:,.0f}",
                size(peak),
            ]
        )
    table(
        (
            "case",
            "candidates tried",
            "min",
            "median",
            "CPU min",
            "runs",
            "candidates/s (min)",
            "traced peak",
        ),
        rows,
    )
    print_speed_check("end")


if __name__ == "__main__":
    main()
