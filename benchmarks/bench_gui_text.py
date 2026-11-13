"""Benchmark the GUI's large-text paths: wrapping, whitespace stripping, Swap and Copy.

Run as ``python benchmarks/bench_gui_text.py`` (``--quick`` uses smaller inputs,
``--no-qos`` allows Windows power throttling). The Tk part is skipped when no display
is available.

Part 1 (Tk, run first so the working-set peak is its own): the real ``App`` methods
on a large secure-mode-sized output: showing the result (wrap and insert), Swap (read
the output back and replace the input), Copy (put the raw output on the clipboard),
each followed by ``update`` so the layout and drawing cost is included, plus the
process working-set growth.

Part 2 (no display): time and ``tracemalloc`` peak of ``controller.wrap_lines`` on hex
and decimal output, and of the whitespace stripping done before ``decode_hex`` on
wrapped hex, against two alternatives (``str.translate`` and ``re.sub``). Peaks are
given as a multiple of the input length in characters (all inputs are ASCII, one byte
per character).
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable

from _common import (
    build_parser,
    peak_rss,
    prefer_full_speed,
    print_header,
    seconds,
    size,
    table,
    traced_peak,
)
from encryptor.gui import controller

_WHITESPACE = re.compile(r"\s+")
_DELETE_WS = str.maketrans("", "", " \t\n\r\x0b\x0c")


def best_time(function: Callable[[], object], runs: int = 3) -> float:
    """Return the minimum wall time of ``runs`` calls."""
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        function()
        best = min(best, time.perf_counter() - started)
    return best


def row(label: str, function: Callable[[], object], chars: int) -> list[str]:
    """Return one table row: label, best time, traced peak and peak per input char."""
    elapsed = best_time(function)
    peak, _ = traced_peak(function)
    return [label, seconds(elapsed), size(peak), f"{peak / chars:.2f}"]


def text_part(raw_bytes: int) -> None:
    """Print the display-free table for ``raw_bytes`` of ciphertext."""
    data = os.urandom(raw_bytes)
    hex_text = data.hex()
    decimal_text = " ".join(map(str, data))
    wrapped = controller.wrap_lines(hex_text)
    rows = [
        row(
            f"wrap_lines, hex ({len(hex_text):,} chars)",
            lambda: controller.wrap_lines(hex_text),
            len(hex_text),
        ),
        row(
            f"wrap_lines, decimal ({len(decimal_text):,} chars)",
            lambda: controller.wrap_lines(decimal_text),
            len(decimal_text),
        ),
        row(
            'strip: "".join(text.split()) (current)', lambda: "".join(wrapped.split()), len(wrapped)
        ),
        row(
            "strip: text.translate(delete whitespace)",
            lambda: wrapped.translate(_DELETE_WS),
            len(wrapped),
        ),
        row('strip: re.sub(r"\\s+", "", text)', lambda: _WHITESPACE.sub("", wrapped), len(wrapped)),
        row(
            "decrypt prep: decode_hex(strip(wrapped))",
            lambda: controller.encoding.decode_hex("".join(wrapped.split())),
            len(wrapped),
        ),
    ]
    table(("operation", "best time", "traced peak", "peak / input char"), rows)


def tk_part(raw_bytes: int) -> None:
    """Print the Tk table for ``raw_bytes`` of ciphertext, or a skip line."""
    try:
        from encryptor.gui import app as app_module

        root, gui = app_module.build_app()
    except Exception as error:
        print(f"Tk part skipped: {type(error).__name__}.")
        return
    try:
        root.update()
        raw = os.urandom(raw_bytes).hex()
        rss_before = peak_rss()
        rows: list[list[str]] = []

        def show() -> None:
            gui._set_output(raw, controller.display_text("encrypt", raw))
            root.update()

        def swap() -> None:
            gui.swap()
            root.update()

        def copy() -> None:
            gui._set_output(raw, "x")
            gui.copy_output()
            root.update()

        for label, function in (("show output (wrap + insert)", show), ("Swap", swap)):
            started = time.perf_counter()
            function()
            rows.append([label, seconds(time.perf_counter() - started)])
        started = time.perf_counter()
        copy()
        rows.append(["Copy (clipboard_append raw)", seconds(time.perf_counter() - started)])
        started = time.perf_counter()
        text = gui.input_text.get("1.0", "end-1c")
        payload = controller.encoding.decode_hex("".join(text.split()))
        rows.append(
            ["read swapped input + strip + decode_hex", seconds(time.perf_counter() - started)]
        )
        if payload != bytes.fromhex(raw):
            raise AssertionError("swapped input does not decode to the original bytes")
        rss_after = peak_rss()
        table((f"Tk, {len(raw):,} hex chars", "wall time"), rows)
        if rss_before is not None and rss_after is not None:
            print(f"Peak working set growth over the Tk steps: {size(rss_after - rss_before)}.")
            print()
    finally:
        root.destroy()


def main() -> None:
    """Run both parts and print the tables."""
    args = build_parser(__doc__ or "").parse_args()
    mode = prefer_full_speed(not args.no_qos)
    print_header("bench_gui_text", mode, args.quick)
    raw_bytes = (1 << 18) if args.quick else (1 << 21)
    print(f"Ciphertext: {raw_bytes:,} random bytes.")
    print()
    tk_part(raw_bytes)
    text_part(raw_bytes)


if __name__ == "__main__":
    main()
