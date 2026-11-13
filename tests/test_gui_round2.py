"""Regression tests for GUI security review round 2 (items R1, R3, R4, R6, R7).

Skipped when tkinter is not installed or no display is available.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator

import pytest

tkinter = pytest.importorskip("tkinter")

# isort: off
from encryptor import classic, secure  # noqa: E402
from encryptor.gui import app as gui_app  # noqa: E402
from encryptor.gui import controller  # noqa: E402

# isort: on

SMALL_BOUND = 4096
FAST_SCRYPT_N = 2**4
DEADLINE_SECONDS = 30.0
PASSPHRASE = "zebra quilt"
TEXT = "hello, world"
CRACK_MESSAGE = "Known plaintext: meet me at the old bridge at nine."

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


def text_of(widget: tkinter.Text) -> str:
    return str(widget.get("1.0", "end-1c"))


# ------------------------------------------------- R1. Ctrl+Enter does not edit text


@pytest.mark.parametrize("name", ["input_text", "crack_plain_text", "crack_cipher_text"])
def test_ctrl_enter_in_a_text_widget_runs_once_without_editing(
    window: Window, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    root, app = window
    if name != "input_text":
        app.notebook.select(app._crack_tab)
    calls: list[None] = []
    monkeypatch.setattr(app, "run", lambda: calls.append(None))
    widget: tkinter.Text = getattr(app, name)
    widget.insert("1.0", "abc def")
    widget.tag_add("sel", "1.0", "end-1c")
    widget.mark_set("insert", "end-1c")
    widget.focus_force()
    root.update()
    widget.event_generate("<Control-Return>")
    root.update()
    assert text_of(widget) == "abc def"
    assert len(calls) == 1


def test_ctrl_enter_outside_text_widgets_still_runs(
    window: Window, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, app = window
    calls: list[None] = []
    monkeypatch.setattr(app, "run", lambda: calls.append(None))
    app.passphrase_entry.focus_force()
    root.update()
    app.passphrase_entry.event_generate("<Control-Return>")
    root.update()
    assert len(calls) == 1


# ---------------------------------------------------- R3. crack masks the passphrase


def test_starting_a_crack_masks_the_passphrase(window: Window, dialogs: Dialogs) -> None:
    root, app = window
    app.passphrase_entry.insert(0, PASSPHRASE)
    app.show_var.set(True)
    app.notebook.select(app._crack_tab)
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 3)
    app.crack_plain_text.insert("1.0", CRACK_MESSAGE)
    app.crack_cipher_text.insert("1.0", ciphertext.hex())
    app.max_offset_entry.insert(0, "16")
    app.run()
    assert app.show_var.get() is False
    assert str(app.passphrase_entry.cget("show")) == "*"
    wait_until_idle(root, app)
    assert dialogs == []


# ------------------------------------------------- R4. Clear drops the pending job


def test_clear_discards_a_pending_cipher_job(
    window: Window, dialogs: Dialogs, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, app = window
    release = threading.Event()
    real_execute = controller._execute_cipher

    def slow_execute(request: controller.CipherRequest, payload: bytes) -> str:
        release.wait(DEADLINE_SECONDS)
        return real_execute(request, payload)

    monkeypatch.setattr(controller, "_execute_cipher", slow_execute)
    app.mode_var.set("classic")
    app.input_text.insert("1.0", TEXT)
    app.passphrase_entry.insert(0, PASSPHRASE)
    app.run()
    job = app._cipher_job
    assert job is not None
    assert is_disabled(app.run_button)
    app.clear()
    assert app.busy is False
    assert not is_disabled(app.run_button)
    assert not is_disabled(app.crack_run_button)
    release.set()
    deadline = time.monotonic() + DEADLINE_SECONDS
    while job.running and time.monotonic() < deadline:
        time.sleep(0.005)
    for _ in range(5):
        root.update()
        time.sleep(controller.POLL_INTERVAL_MS / 1000)
    root.update()
    assert text_of(app.output_text) == ""
    assert app._output_raw == ""
    assert app.busy is False
    assert dialogs == []


# ----------------------------- T1. no new cipher job while a dropped one still runs


def test_run_after_clear_waits_for_the_dropped_cipher_job(
    window: Window, dialogs: Dialogs, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, app = window
    release = threading.Event()
    real_execute = controller._execute_cipher

    def slow_execute(request: controller.CipherRequest, payload: bytes) -> str:
        release.wait(DEADLINE_SECONDS)
        return real_execute(request, payload)

    monkeypatch.setattr(controller, "_execute_cipher", slow_execute)
    app.mode_var.set("classic")
    app.input_text.insert("1.0", TEXT)
    app.passphrase_entry.insert(0, PASSPHRASE)
    app.run()
    dropped = app._cipher_job
    assert dropped is not None
    app.clear()

    app.input_text.insert("1.0", TEXT)
    app.passphrase_entry.insert(0, PASSPHRASE)
    app.run()
    assert app._cipher_job is None
    assert app.busy is False
    assert app.status_var.get() == "Previous operation still finishing..."
    assert app.passphrase_entry.get() == PASSPHRASE

    release.set()
    deadline = time.monotonic() + DEADLINE_SECONDS
    while dropped.running and time.monotonic() < deadline:
        time.sleep(0.005)
    assert not dropped.running
    root.update()
    assert text_of(app.output_text) == ""

    app.run()
    assert app._cipher_job is not None
    assert app._cipher_job is not dropped
    wait_until_idle(root, app)
    assert app._output_raw != ""
    assert dialogs == []


# ------------------------------------------ R6. not-found does not rely on the title


def test_not_found_uses_the_failed_flag_not_the_dialog_title(
    window: Window, dialogs: Dialogs, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, app = window
    real_describe = controller.describe_error

    def retitled(error: BaseException) -> controller.ErrorInfo:
        info = real_describe(error)
        return controller.ErrorInfo(f"Renamed {info.title}", info.message)

    monkeypatch.setattr(controller, "describe_error", retitled)
    app.notebook.select(app._crack_tab)
    ciphertext = classic.encrypt_at_offset(CRACK_MESSAGE.encode("utf-8"), 100)
    app.crack_plain_text.insert("1.0", CRACK_MESSAGE)
    app.crack_cipher_text.insert("1.0", ciphertext.hex())
    app.max_offset_entry.insert(0, "50")
    app.run()
    wait_until_idle(root, app)
    assert dialogs == []
    assert app.status_var.get() == "Offset not found."
    assert "No matching offset" in text_of(app.crack_result_text)


# ------------------------------------------------ R7. output does not export selection


def test_output_text_does_not_export_its_selection(window: Window) -> None:
    _root, app = window
    assert not bool(int(str(app.output_text.cget("exportselection"))))
