"""Regression tests for GUI security review round 1 (items S1-S5).

Skipped when tkinter is not installed or no display is available.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterator

import pytest

tkinter = pytest.importorskip("tkinter")

# isort: off
from encryptor import classic, secure  # noqa: E402
from encryptor.gui import app as gui_app  # noqa: E402

# isort: on

SMALL_BOUND = 4096
FAST_SCRYPT_N = 2**4
DEADLINE_SECONDS = 30.0
PASSPHRASE = "zebra quilt"
TEXT = "hello, world"
SENTINEL = "clipboard sentinel"

Window = tuple[tkinter.Tk, gui_app.App]
Dialogs = list[tuple[str, str]]


@pytest.fixture(autouse=True)
def fast_core(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(classic, "OFFSET_BOUND", SMALL_BOUND)
    monkeypatch.setattr(secure, "SCRYPT_N", FAST_SCRYPT_N)


@pytest.fixture
def dialogs(monkeypatch: pytest.MonkeyPatch) -> Dialogs:
    """Record error dialogs instead of opening a modal window."""
    shown: Dialogs = []

    def fake_showerror(title: str, message: str, **_kwargs: object) -> str:
        shown.append((title, message))
        return "ok"

    monkeypatch.setattr(gui_app.messagebox, "showerror", fake_showerror)
    return shown


@pytest.fixture
def window() -> Iterator[Window]:
    try:
        root, app = gui_app.build_app()
    except tkinter.TclError:
        pytest.skip("no display available")
    try:
        root.update()
        yield root, app
    finally:
        with contextlib.suppress(tkinter.TclError):  # already destroyed
            root.destroy()


def wait_until_idle(root: tkinter.Tk, app: gui_app.App) -> None:
    deadline = time.monotonic() + DEADLINE_SECONDS
    while app.busy:
        if time.monotonic() > deadline:
            pytest.fail(f"the operation did not finish within {DEADLINE_SECONDS} s")
        root.update()
        time.sleep(0.005)
    root.update()


def is_disabled(widget: tkinter.Widget) -> bool:
    return bool(widget.instate(["disabled"]))  # type: ignore[attr-defined]


def fill(app: gui_app.App, text: str = TEXT, passphrase: str = PASSPHRASE) -> None:
    app.mode_var.set("classic")
    app.input_text.insert("1.0", text)
    app.passphrase_entry.insert(0, passphrase)


# ---------------------------------------------------------------- S1. no copy / export


def test_passphrase_entry_does_not_export_its_selection(window: Window) -> None:
    _root, app = window
    assert not bool(int(str(app.passphrase_entry.cget("exportselection"))))


@pytest.mark.parametrize("virtual_event", ["<<Copy>>", "<<Cut>>"])
def test_passphrase_cannot_be_copied_or_cut(window: Window, virtual_event: str) -> None:
    root, app = window
    app.show_var.set(True)
    app.passphrase_entry.insert(0, PASSPHRASE)
    app.passphrase_entry.focus_force()
    app.passphrase_entry.select_range(0, "end")
    root.clipboard_clear()
    root.clipboard_append(SENTINEL)
    root.update()
    app.passphrase_entry.event_generate(virtual_event)
    root.update()
    assert root.clipboard_get() == SENTINEL
    assert app.passphrase_entry.get() == PASSPHRASE


# ------------------------------------------------------------ S2. Show resets to masked


def test_run_resets_the_show_toggle(window: Window, dialogs: Dialogs) -> None:
    root, app = window
    app.keep_var.set(True)
    fill(app)
    app.show_var.set(True)
    app.run()
    assert app.show_var.get() is False
    assert str(app.passphrase_entry.cget("show")) == "*"
    wait_until_idle(root, app)
    assert dialogs == []


def test_clear_resets_the_show_toggle(window: Window) -> None:
    _root, app = window
    app.show_var.set(True)
    app.clear()
    assert app.show_var.get() is False
    assert str(app.passphrase_entry.cget("show")) == "*"


# ------------------------------------------------------- S3. poll survives a bad event


def test_poll_recovers_when_applying_an_event_raises(
    window: Window, dialogs: Dialogs, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, app = window

    def broken(_event: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(app, "_apply_cipher_event", broken)
    fill(app)
    app.run()
    deadline = time.monotonic() + DEADLINE_SECONDS
    while app.busy and time.monotonic() < deadline:
        root.update()
        time.sleep(0.005)
    root.update()
    assert app.busy is False
    assert not is_disabled(app.run_button)
    assert not is_disabled(app.crack_run_button)
    assert dialogs == [("Unexpected error", "An unexpected error occurred (RuntimeError).")]


# ------------------------------------------------------------- S4. nothing after close


def test_poll_after_close_does_not_touch_destroyed_widgets(
    window: Window, dialogs: Dialogs
) -> None:
    _root, app = window
    fill(app)
    app.run()
    job = app._cipher_job
    assert job is not None
    app._on_close()
    deadline = time.monotonic() + DEADLINE_SECONDS
    while job.running and time.monotonic() < deadline:
        time.sleep(0.005)
    app._poll()  # must neither raise TclError nor reschedule
    assert app._after_id is None
    app._report_callback_exception(RuntimeError, RuntimeError("late"), None)
    assert dialogs == []
    app._on_close()  # a second close is harmless


def test_closing_from_an_error_dialog_is_clean(
    window: Window, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, app = window
    shown: Dialogs = []

    def close_while_open(title: str, message: str, **_kwargs: object) -> str:
        shown.append((title, message))
        app._on_close()
        return "ok"

    monkeypatch.setattr(gui_app.messagebox, "showerror", close_while_open)
    app.mode_var.set("secure")
    app.action_var.set("decrypt")
    app.input_text.insert("1.0", "01" + "00" * 60)
    app.passphrase_entry.insert(0, PASSPHRASE)
    app.run()
    deadline = time.monotonic() + DEADLINE_SECONDS
    while not shown and time.monotonic() < deadline:
        root.update()
        time.sleep(0.005)
    assert shown and shown[0][0] == "Decryption failed"
    assert app._after_id is None


# --------------------------------------------- S5. validate before clearing passphrase


@pytest.mark.parametrize(
    ("action", "text", "decimal"),
    [
        ("encrypt", "", False),
        ("decrypt", "", False),
        ("decrypt", "not hex", False),
        ("decrypt", "abc", False),
        ("decrypt", "1 2 999", True),
    ],
)
def test_invalid_input_keeps_the_passphrase(
    window: Window, dialogs: Dialogs, action: str, text: str, decimal: bool
) -> None:
    root, app = window
    fill(app, text=text)
    app.action_var.set(action)
    app.decimal_var.set(decimal)
    app.run()
    assert app.busy is False
    assert app.passphrase_entry.get() == PASSPHRASE
    assert len(dialogs) == 1
    assert dialogs[0][0] == "Invalid input"
    assert PASSPHRASE not in dialogs[0][1]
    assert not is_disabled(app.run_button)
    root.update()


def test_missing_passphrase_shows_a_dialog_without_starting_a_job(
    window: Window, dialogs: Dialogs
) -> None:
    _root, app = window
    fill(app, passphrase="")
    app.run()
    assert app.busy is False
    assert dialogs == [("Invalid input", "enter a passphrase")]


def test_valid_input_still_clears_the_passphrase(window: Window, dialogs: Dialogs) -> None:
    root, app = window
    fill(app)
    app.run()
    assert app.passphrase_entry.get() == ""
    wait_until_idle(root, app)
    assert dialogs == []
    expected = classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE).hex()
    assert str(app.output_text.get("1.0", "end-1c")) == expected
