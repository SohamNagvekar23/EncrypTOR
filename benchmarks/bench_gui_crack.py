"""Benchmark the GUI's crack search: overhead, progress, cancel latency, UI ticks.

Run as ``python benchmarks/bench_gui_crack.py`` (``--quick`` uses a 2**15 range,
``--no-qos`` allows Windows power throttling, ``--runs N`` sets repetitions).

Measures, for a miss over the full range (the worst case):

1. One plain ``crack.crack`` (no callback) over the full range versus
   ``controller.run_crack`` (one ``crack.crack`` call with the ``progress`` hook), plus
   the same for a hit at the last offset of the range. Also the number of progress
   reports and the longest gap between two of them.
2. Worst-case cancel latency: ``Job.cancel()`` is called right after the progress
   event that starts the longest digit chunk (the last full-width one; the final chunk
   is usually a short remainder); the latency is the time until ``Failed`` arrives,
   and the job must report ``cancelled``.
3. UI-thread responsiveness while the crack runs on a worker: the main thread sleeps
   ``POLL_INTERVAL_MS`` in a loop, like a ``root.after`` poll, and records how late each
   tick wakes up (GIL contention from the pure-Python search).
"""

from __future__ import annotations

import contextlib
import itertools
import statistics
import threading
import time
from collections.abc import Callable

from _common import build_parser, prefer_full_speed, print_header, print_speed_check, table
from encryptor import OffsetNotFoundError, classic
from encryptor import crack as crack_module
from encryptor.gui import controller

PLAINTEXT = b"known plaintext for the crack demo"
QUICK_LIMIT = 1 << 15


def timed(function: Callable[[], object]) -> float:
    """Return the wall time of one call, swallowing ``OffsetNotFoundError``."""
    started = time.perf_counter()
    with contextlib.suppress(OffsetNotFoundError):
        function()
    return time.perf_counter() - started


def summary(values: list[float]) -> tuple[str, str]:
    """Return (min, median) formatted in seconds."""
    return f"{min(values):.3f} s", f"{statistics.median(values):.3f} s"


def progress_gaps(request: controller.CrackRequest) -> tuple[int, float, int]:
    """Run one miss with a progress callback.

    Returns (number of reports, longest gap in seconds between consecutive reports or
    the end, ``searched`` of the report that starts that longest gap).
    """
    stamps: list[float] = [time.perf_counter()]
    reports: list[controller.CrackProgress] = []

    def record(item: controller.CrackProgress) -> None:
        stamps.append(time.perf_counter())
        reports.append(item)

    with contextlib.suppress(OffsetNotFoundError):
        controller.run_crack(request, cancel=threading.Event(), progress=record)
    stamps.append(time.perf_counter())
    gaps = [high - low for low, high in itertools.pairwise(stamps)]
    longest = max(range(1, len(gaps)), key=gaps.__getitem__)
    return len(reports), gaps[longest], reports[longest - 1].searched


def cancel_latency(request: controller.CrackRequest, final_from: int) -> tuple[float, float, bool]:
    """Cancel right after the progress report with ``searched >= final_from``.

    Returns (latency, total job time, whether the job reported ``cancelled``).
    """
    started = time.perf_counter()
    job = controller.start_crack(request)
    cancelled_at: float | None = None
    while True:
        for event in job.poll():
            if isinstance(event, controller.Progress):
                if event.value.searched >= final_from and cancelled_at is None:
                    job.cancel()
                    cancelled_at = time.perf_counter()
            elif isinstance(event, controller.Failed):
                end = time.perf_counter()
                if cancelled_at is None:
                    raise AssertionError("job failed before the final chunk started")
                return end - cancelled_at, end - started, event.cancelled
            else:
                raise AssertionError("job finished without being cancelled")
        time.sleep(0.001)


def ui_ticks(request: controller.CrackRequest) -> list[float]:
    """Run a crack job and return how late each simulated poll tick woke up (seconds)."""
    interval = controller.POLL_INTERVAL_MS / 1000.0
    lateness: list[float] = []
    job = controller.start_crack(request)
    while True:
        before = time.perf_counter()
        time.sleep(interval)
        lateness.append(time.perf_counter() - before - interval)
        events = job.poll()
        if any(not isinstance(event, controller.Progress) for event in events):
            return lateness


def main() -> None:
    """Run the crack benchmarks and print the tables."""
    parser = build_parser(__doc__ or "")
    parser.add_argument("--runs", type=int, default=3, help="repetitions per case")
    args = parser.parse_args()
    mode = prefer_full_speed(not args.no_qos)
    print_header("bench_gui_crack", mode, args.quick)
    limit = QUICK_LIMIT if args.quick else classic.OFFSET_BOUND
    runs: int = max(1, args.runs)
    miss = classic.encrypt_at_offset(PLAINTEXT, limit + 1000)
    hit = classic.encrypt_at_offset(PLAINTEXT, limit - 1)
    miss_request = controller.CrackRequest(PLAINTEXT.decode(), miss.hex(), limit)
    hit_request = controller.CrackRequest(PLAINTEXT.decode(), hit.hex(), limit)
    never = threading.Event()

    print(
        f"Message: {len(PLAINTEXT)} bytes, range [0, {limit}), progress chunk "
        f"{crack_module.CRACK_PROGRESS_CHUNK_DIGITS} digits, runs {runs}."
    )
    print()

    plain_miss = [timed(lambda: crack_module.crack(PLAINTEXT, miss, limit)) for _ in range(runs)]
    hooked_miss = [
        timed(lambda: controller.run_crack(miss_request, cancel=never)) for _ in range(runs)
    ]
    plain_hit = [timed(lambda: crack_module.crack(PLAINTEXT, hit, limit)) for _ in range(runs)]
    hooked_hit = [
        timed(lambda: controller.run_crack(hit_request, cancel=never)) for _ in range(runs)
    ]
    table(
        ("case", "plain crack.crack min", "run_crack (progress) min", "ratio (min)"),
        [
            [
                f"miss over [0, {limit})",
                summary(plain_miss)[0],
                summary(hooked_miss)[0],
                f"{min(hooked_miss) / min(plain_miss):.2f}x",
            ],
            [
                f"hit at offset {limit - 1}",
                summary(plain_hit)[0],
                summary(hooked_hit)[0],
                f"{min(hooked_hit) / min(plain_hit):.2f}x",
            ],
        ],
    )
    print()

    count, gap, final_from = progress_gaps(miss_request)
    print(f"Progress reports per miss: {count}; longest gap between reports: {gap:.3f} s.")
    latencies = [cancel_latency(miss_request, final_from) for _ in range(runs)]
    lat = [value for value, _, _ in latencies]
    honoured = sum(1 for _, _, cancelled in latencies if cancelled)
    print(
        f"Worst-case cancel latency (cancel at start of the longest chunk): "
        f"min {min(lat):.3f} s, median {statistics.median(lat):.3f} s, max {max(lat):.3f} s; "
        f"reported as cancelled in {honoured} of {len(latencies)} runs."
    )

    lateness = ui_ticks(miss_request)
    lateness_ms = sorted(value * 1000.0 for value in lateness)
    p99 = lateness_ms[min(len(lateness_ms) - 1, int(0.99 * len(lateness_ms)))]
    print(
        f"UI tick lateness during a crack ({len(lateness_ms)} ticks of "
        f"{controller.POLL_INTERVAL_MS} ms): median {statistics.median(lateness_ms):.1f} ms, "
        f"p99 {p99:.1f} ms, max {lateness_ms[-1]:.1f} ms."
    )
    print_speed_check("end")


if __name__ == "__main__":
    main()
