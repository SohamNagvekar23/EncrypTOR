"""Sweep the crack search's digit-chunk width: total time versus cancel latency.

Run as ``python benchmarks/bench_crack_chunks.py`` (``--quick`` uses a 2**15 range,
``--no-qos`` allows Windows power throttling, ``--runs N`` sets repetitions).

``crack.crack`` with a ``progress`` callback grows its digit table in
``CRACK_PROGRESS_CHUNK_DIGITS`` chunks and checks for a stop between chunks, so the
chunk width trades total search time (every chunk pays the BBP cost of its position
again) against cancel latency (the time of the last, most expensive chunk). For each
width this script patches that constant, runs a full-range miss with an always-true
callback and records the total time and the longest gap between callbacks. It also
times the callback-free path (``progress=None``, the CLI) for reference, and two
time-budgeted schedules evaluated on the bare digit generator (``pi_hex_digits``),
where each chunk's width is chosen so its estimated cost stays under a budget.
"""

from __future__ import annotations

import contextlib
import itertools
import time
from collections.abc import Callable

from _common import build_parser, prefer_full_speed, print_header, print_speed_check, table
from encryptor import OffsetNotFoundError, classic
from encryptor import crack as crack_module
from encryptor.pi_stream import pi_hex_digits

PLAINTEXT = b"known plaintext for the crack demo"
QUICK_LIMIT = 1 << 15
FIXED = 2048
WIDTHS = (4096, 8192, 12288, 16384, 24576, 32768)


def run_hooked(ciphertext: bytes, limit: int, width: int) -> tuple[float, float, float]:
    """Run a hooked miss with chunk ``width``; return (total, longest gap, last gap)."""
    stamps: list[float] = []

    def hook(_tried: int, _total: int) -> bool:
        stamps.append(time.perf_counter())
        return True

    saved = crack_module.CRACK_PROGRESS_CHUNK_DIGITS
    crack_module.CRACK_PROGRESS_CHUNK_DIGITS = width  # type: ignore[misc]
    try:
        started = time.perf_counter()
        with contextlib.suppress(OffsetNotFoundError):
            crack_module.crack(PLAINTEXT, ciphertext, limit, progress=hook)
        end = time.perf_counter()
    finally:
        crack_module.CRACK_PROGRESS_CHUNK_DIGITS = saved  # type: ignore[misc]
    stamps.append(end)
    gaps = [high - low for low, high in itertools.pairwise(stamps)]
    return end - started, max(gaps), gaps[-1]


def run_plain(ciphertext: bytes, limit: int) -> float:
    """Run the callback-free miss (the CLI path); return its wall time."""
    started = time.perf_counter()
    with contextlib.suppress(OffsetNotFoundError):
        crack_module.crack(PLAINTEXT, ciphertext, limit)
    return time.perf_counter() - started


def budget_schedule(total: int, budget_units: float, cap: int) -> list[tuple[int, int]]:
    """Chunks (position, width) whose cost estimate (d + c) * (FIXED + c) <= budget.

    The model follows ``pi_hex_int``: about (d + c) / 8 groups, each one modular
    exponentiation (a fixed cost, worth about ``FIXED`` digits of division) plus one
    division of 4c + 64 bits. ``FIXED`` is fitted from the width sweep.
    Widths are multiples of 1024, at least 4096 and at most ``cap``.
    """
    chunks: list[tuple[int, int]] = []
    position = 0
    while position < total:
        width = cap
        while width > 4096 and (position + width) * (FIXED + width) > budget_units:
            width -= 1024
        width = min(width, total - position)
        chunks.append((position, width))
        position += width
    return chunks


def run_schedule(chunks: list[tuple[int, int]]) -> tuple[float, float, float]:
    """Generate the digits of ``chunks``; return (total, longest chunk, last chunk)."""
    times: list[float] = []
    for position, width in chunks:
        started = time.perf_counter()
        pi_hex_digits(position, width)
        times.append(time.perf_counter() - started)
    return sum(times), max(times), times[-1]


def best_of(runs: int, function: Callable[[], tuple[float, float, float]]) -> tuple[float, ...]:
    """Run ``function`` ``runs`` times; return the run with the smallest total."""
    return min((function() for _ in range(runs)), key=lambda result: result[0])


def main() -> None:
    """Run the sweep and print the tables."""
    parser = build_parser(__doc__ or "")
    parser.add_argument("--runs", type=int, default=2, help="repetitions per case")
    args = parser.parse_args()
    mode = prefer_full_speed(not args.no_qos)
    print_header("bench_crack_chunks", mode, args.quick)
    limit = QUICK_LIMIT if args.quick else classic.OFFSET_BOUND
    runs: int = max(1, args.runs)
    miss = classic.encrypt_at_offset(PLAINTEXT, limit + 1000)

    plain = min(run_plain(miss, limit) for _ in range(runs))
    print(
        f"Range [0, {limit}), {len(PLAINTEXT)}-byte message, runs {runs}. "
        f"progress=None (CRACK_CHUNK_DIGITS={crack_module.CRACK_CHUNK_DIGITS}): {plain:.3f} s."
    )
    print()

    rows: list[list[str]] = []
    for width in WIDTHS:
        total, longest, last = best_of(runs, lambda w=width: run_hooked(miss, limit, w))
        rows.append(
            [
                str(width),
                f"{total:.3f} s",
                f"{total / plain:.2f}x",
                f"{longest:.3f} s",
                f"{last:.3f} s",
            ]
        )
    table(
        ("progress chunk", "hooked miss (best)", "vs progress=None", "longest gap", "last gap"),
        rows,
    )

    digits = limit - 1 + 2 * crack_module.CRACK_PREFIX_BYTES
    reference = best_of(runs, lambda: run_schedule(budget_schedule(digits, 1e18, 16384)))
    fixed_count = str(len(budget_schedule(digits, 1e18, 16384)))
    schedule_rows: list[list[str]] = [
        ["fixed 16384", fixed_count, f"{reference[0]:.3f} s", "1.00x", f"{reference[1]:.3f} s"]
    ]
    for label, budget, cap in (
        ("budget = last 8192 chunk, cap 16384", (limit + 8192) * (FIXED + 8192), 16384),
        ("budget = last 8192 chunk, cap 32768", (limit + 8192) * (FIXED + 8192), 32768),
    ):
        chunks = budget_schedule(digits, budget, cap)
        total, longest, _ = best_of(runs, lambda c=chunks: run_schedule(c))
        schedule_rows.append(
            [
                label,
                str(len(chunks)),
                f"{total:.3f} s",
                f"{total / reference[0]:.2f}x",
                f"{longest:.3f} s",
            ]
        )
    table(
        ("digit schedule (generator only)", "chunks", "total", "vs fixed 16384", "longest chunk"),
        schedule_rows,
    )
    print_speed_check("end")


if __name__ == "__main__":
    main()
