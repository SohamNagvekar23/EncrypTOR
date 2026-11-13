"""Regression tests for GUI performance review round 1 (items P1, P2 and P4).

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
from encryptor.gui import controller  # noqa: E402

# isort: on

SMALL_BOUND = 4096
FAST_SCRYPT_N = 2**4
DEADLINE_SECONDS = 30.0
PASSPHRASE = "zebra quilt"
LONG_TEXT = "The quick brown fox jumps over the lazy dog. " * 10

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


def text_of(widget: tkinter.Text) -> str:
    return str(widget.get("1.0", "end-1c"))


def try_undo(widget: tkinter.Text) -> None:
    """Press Ctrl+Z programmatically; "nothing to undo" is the expected outcome."""
    with contextlib.suppress(tkinter.TclError):
        widget.edit_undo()


def encrypt(root: tkinter.Tk, app: gui_app.App, mode: str, text: str, decimal: bool) -> None:
    app.keep_var.set(True)
    app.mode_var.set(mode)
    app.action_var.set("encrypt")
    app.decimal_var.set(decimal)
    app.input_text.insert("1.0", text)
    app.passphrase_entry.insert(0, PASSPHRASE)
    app.run()
    wait_until_idle(root, app)


# ----------------------------------------------------------------- P1. wrapped output


@pytest.mark.parametrize(
    ("mode", "decimal"),
    [("classic", False), ("classic", True), ("secure", False)],
    ids=["classic-hex", "classic-decimal", "secure-hex"],
)
def test_long_output_is_shown_in_short_lines(
    window: Window, dialogs: Dialogs, mode: str, decimal: bool
) -> None:
    root, app = window
    encrypt(root, app, mode, LONG_TEXT, decimal)
    assert dialogs == []
    shown = text_of(app.output_text)
    lines = shown.split("\n")
    assert len(lines) > 1
    assert all(len(line) <= controller.OUTPUT_LINE_WIDTH for line in lines)


@pytest.mark.parametrize("decimal", [False, True], ids=["hex", "decimal"])
def test_copy_gives_the_unwrapped_output(window: Window, dialogs: Dialogs, decimal: bool) -> None:
    root, app = window
    encrypt(root, app, "classic", LONG_TEXT, decimal)
    raw = classic.encrypt(LONG_TEXT.encode("utf-8"), PASSPHRASE)
    expected = " ".join(map(str, raw)) if decimal else raw.hex()
    root.clipboard_clear()
    app.copy_output()
    assert root.clipboard_get() == expected
    assert "\n" not in root.clipboard_get()


@pytest.mark.parametrize(
    ("mode", "decimal"),
    [("classic", False), ("classic", True), ("secure", False)],
    ids=["classic-hex", "classic-decimal", "secure-hex"],
)
def test_swap_wrapped_output_then_decrypt_round_trips(
    window: Window, dialogs: Dialogs, mode: str, decimal: bool
) -> None:
    root, app = window
    encrypt(root, app, mode, LONG_TEXT, decimal)
    app.swap()
    assert "\n" in text_of(app.input_text)
    app.action_var.set("decrypt")
    app.run()
    wait_until_idle(root, app)
    assert dialogs == []
    assert text_of(app.output_text) == LONG_TEXT


def test_copy_after_decrypt_gives_the_plaintext(window: Window, dialogs: Dialogs) -> None:
    root, app = window
    encrypt(root, app, "classic", LONG_TEXT, False)
    app.swap()
    app.action_var.set("decrypt")
    app.run()
    wait_until_idle(root, app)
    root.clipboard_clear()
    app.copy_output()
    assert root.clipboard_get() == LONG_TEXT


def test_clear_forgets_the_copy_buffer(window: Window, dialogs: Dialogs) -> None:
    root, app = window
    encrypt(root, app, "classic", LONG_TEXT, False)
    app.clear()
    root.clipboard_clear()
    root.clipboard_append("sentinel")
    app.copy_output()
    assert root.clipboard_get() == "sentinel"


# ------------------------------------------------------------------ P2. cancel status


def test_cancel_status_does_not_mention_stages(window: Window, dialogs: Dialogs) -> None:
    root, app = window
    app.notebook.select(1)
    root.update()
    ciphertext = classic.encrypt_at_offset(b"known plaintext", SMALL_BOUND + 10)
    app.crack_plain_text.insert("1.0", "known plaintext")
    app.crack_cipher_text.insert("1.0", ciphertext.hex())
    app.run()
    app.cancel_crack()
    assert "stage" not in app.status_var.get().lower()
    wait_until_idle(root, app)
    assert app.status_var.get() == "The search was cancelled."
    assert dialogs == []


# --------------------------------------------------------------------- P4. undo stack


def test_output_and_result_widgets_have_no_undo(window: Window) -> None:
    _root, app = window
    assert not bool(int(app.output_text.cget("undo")))
    assert not bool(int(app.crack_result_text.cget("undo")))


def test_clear_cannot_be_undone(window: Window) -> None:
    root, app = window
    app.input_text.insert("1.0", "secret plaintext")
    app.input_text.edit_separator()
    root.update()
    app.clear()
    try_undo(app.input_text)
    assert text_of(app.input_text) == ""


def test_swap_cannot_be_undone_back_to_the_old_input(window: Window, dialogs: Dialogs) -> None:
    root, app = window
    encrypt(root, app, "classic", "secret plaintext", False)
    shown = text_of(app.output_text)
    app.input_text.edit_separator()
    app.swap()
    try_undo(app.input_text)
    assert text_of(app.input_text) == shown
    assert "secret plaintext" not in text_of(app.input_text)


def test_crack_tab_clear_cannot_be_undone(window: Window) -> None:
    root, app = window
    app.notebook.select(1)
    root.update()
    app.crack_plain_text.insert("1.0", "known plaintext")
    app.crack_cipher_text.insert("1.0", "00ff")
    app.clear()
    try_undo(app.crack_plain_text)
    try_undo(app.crack_cipher_text)
    assert text_of(app.crack_plain_text) == ""
    assert text_of(app.crack_cipher_text) == ""
