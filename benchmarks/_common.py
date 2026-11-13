"""Shared helpers for the benchmark scripts (standard library only).

Timing method: every case is run several times and reported as minimum and median
wall time (``time.perf_counter``) plus the minimum CPU time (``time.process_time``).
When CPU time is close to wall time, a slow run was not waiting for the CPU: the core
itself was slower (a lower clock, or an efficiency core).

Why ``prefer_full_speed`` exists. On Windows 11 a CPU-bound process that does not own
the foreground window is clamped to an "efficiency" speed after a few seconds (power
throttling, also called EcoQoS), and on hybrid CPUs it may be moved to an efficiency
core. On the development machine that makes the same call take 0.29 s, 0.43 s or
1.0 s. The scripts therefore opt out of power throttling by default so the numbers
describe the code and not the scheduler; ``--no-qos`` measures the throttled case.
"""

from __future__ import annotations

import argparse
import platform
import statistics
import sys
import time
import tracemalloc
from collections.abc import Callable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Timing:
    """Wall and CPU seconds over ``runs`` repetitions of one case."""

    best: float
    median: float
    cpu_best: float
    runs: int


def build_parser(description: str) -> argparse.ArgumentParser:
    """Return the argument parser shared by the benchmark scripts."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--quick",
        action="store_true",
        help="run a reduced set that finishes in well under a minute",
    )
    parser.add_argument(
        "--no-qos",
        action="store_true",
        help="do not opt out of Windows power throttling (measure a background process)",
    )
    return parser


def prefer_full_speed(enabled: bool = True) -> str:
    """Opt this process out of Windows power throttling; return a description.

    Uses ``SetProcessInformation(ProcessPowerThrottling)`` with the execution-speed
    control bit set and the state bit clear ("HighQoS"). A no-op on other systems.
    """
    if not enabled:
        return "default scheduling (power throttling allowed)"
    if sys.platform != "win32":
        return "default scheduling"
    import ctypes

    class _PowerThrottling(ctypes.Structure):
        _fields_ = (
            ("version", ctypes.c_ulong),
            ("control_mask", ctypes.c_ulong),
            ("state_mask", ctypes.c_ulong),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.SetProcessInformation.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
    )
    state = _PowerThrottling(1, 1, 0)
    process_power_throttling = 4
    done = kernel32.SetProcessInformation(
        kernel32.GetCurrentProcess(),
        process_power_throttling,
        ctypes.byref(state),
        ctypes.sizeof(state),
    )
    if done:
        return "Windows power throttling disabled for this process (HighQoS)"
    return "default scheduling (could not disable power throttling)"


def cpu_name() -> str:
    """Return the processor model name, as precisely as the platform allows."""
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:
                return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        except OSError:
            pass
    return platform.processor() or platform.machine()


def peak_rss() -> int | None:
    """Return the peak resident memory of this process in bytes, if available.

    Unlike ``tracemalloc`` this includes memory allocated by C libraries, for example
    the scrypt work area inside OpenSSL. The value only ever grows.
    """
    if sys.platform == "win32":
        import ctypes

        class _Counters(ctypes.Structure):
            _fields_ = (
                ("cb", ctypes.c_ulong),
                ("page_fault_count", ctypes.c_ulong),
                ("peak_working_set_size", ctypes.c_size_t),
                ("working_set_size", ctypes.c_size_t),
                ("quota_peak_paged_pool_usage", ctypes.c_size_t),
                ("quota_paged_pool_usage", ctypes.c_size_t),
                ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
                ("quota_non_paged_pool_usage", ctypes.c_size_t),
                ("pagefile_usage", ctypes.c_size_t),
                ("peak_pagefile_usage", ctypes.c_size_t),
            )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.K32GetProcessMemoryInfo.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
        )
        counters = _Counters()
        counters.cb = ctypes.sizeof(counters)
        if kernel32.K32GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            return int(counters.peak_working_set_size)
        return None
    try:
        import resource
    except ImportError:
        return None
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak) if sys.platform == "darwin" else int(peak) * 1024


def print_header(title: str, mode: str, quick: bool) -> None:
    """Print the title and the machine line that every result table needs."""
    print(f"## {title}")
    print()
    print(
        f"Machine: {cpu_name()}, {platform.system()} {platform.release()} "
        f"({platform.version()}). Python {platform.python_version()} "
        f"({platform.python_implementation()})."
    )
    print(f"Scheduling: {mode}. Set: {'quick' if quick else 'full'}.")
    print()
    print_speed_check("start")


def speed_check() -> float:
    """Return the best of three timings of a fixed big-integer workload, in seconds.

    The workload (modular exponentiations like those of BBP) does not depend on the
    package, so its time changes only when the CPU itself runs faster or slower.
    """
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        total = 0
        for k in range(20000):
            total += pow(16, 131071 - k, 8 * k + 1)
        best = min(best, time.perf_counter() - started)
    return best


def print_speed_check(moment: str) -> None:
    """Print the CPU speed check, so a clock change during a run is visible.

    Laptop CPUs run faster for the first seconds or minutes of load than they can
    sustain; compare the value at the start and at the end of a run before comparing
    tables from different runs.
    """
    print(f"CPU speed check at {moment}: {seconds(speed_check())} (fixed workload).")
    print()
    sys.stdout.flush()


def measure(function: Callable[[], object], quick: bool = False) -> Timing:
    """Time ``function`` repeatedly and return minimum and median.

    The number of runs depends on the first run: 5 runs under 1 s, 3 runs under
    30 s, otherwise 2 (quick set: 3 runs under 1 s, otherwise 1).
    """
    walls: list[float] = []
    cpus: list[float] = []

    def once() -> None:
        cpu = time.process_time()
        wall = time.perf_counter()
        function()
        walls.append(time.perf_counter() - wall)
        cpus.append(time.process_time() - cpu)

    once()
    first = walls[0]
    limits = ((1.0, 3),) if quick else ((1.0, 5), (30.0, 3))
    runs = next((count for limit, count in limits if first < limit), 1 if quick else 2)
    for _ in range(runs - 1):
        once()
    return Timing(min(walls), statistics.median(walls), min(cpus), runs)


def traced_peak(function: Callable[[], object]) -> tuple[int, int]:
    """Run ``function`` under ``tracemalloc``; return (peak bytes, result length).

    The result is kept alive until the peak is read, so the peak includes the
    output. Inputs created before the call are not counted. The length is 0 for
    results without ``len``. ``tracemalloc`` slows allocation-heavy code several
    times over, so this is always a separate run from the timed ones.
    """
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        result = function()
        peak = tracemalloc.get_traced_memory()[1] - before
    finally:
        tracemalloc.stop()
    size = len(result) if isinstance(result, bytes | bytearray | str) else 0
    return peak, size


def cpu_seconds(timing: Timing) -> str:
    """Format the CPU time, or a dash when it is below the clock resolution.

    ``time.process_time`` ticks in steps of about 16 ms on Windows, so it says
    nothing useful about runs shorter than a few ticks.
    """
    return seconds(timing.cpu_best) if timing.best >= 0.2 else "-"


def seconds(value: float) -> str:
    """Format a duration with a unit that keeps three significant digits."""
    if value < 1e-3:
        return f"{value * 1e6:.1f} us"
    if value < 1.0:
        return f"{value * 1e3:.1f} ms"
    return f"{value:.2f} s"


def size(value: float) -> str:
    """Format a byte count with a binary unit."""
    for unit in ("B", "KiB", "MiB"):
        if abs(value) < 1024 or unit == "MiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def rate(amount: float, elapsed: float, unit: str) -> str:
    """Format ``amount / elapsed`` with thousands separators."""
    if elapsed <= 0:
        return "n/a"
    value = amount / elapsed
    return f"{value:,.0f} {unit}" if value >= 100 else f"{value:,.1f} {unit}"


def table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    """Print a Markdown table followed by a blank line."""
    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        print("| " + " | ".join(row) + " |")
    print()
    sys.stdout.flush()
