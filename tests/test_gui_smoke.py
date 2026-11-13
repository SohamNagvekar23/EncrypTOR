"""Headless smoke test for encryptor.gui.app: builds the real window and drives it.

Skipped when tkinter is not installed or no display is available.

App contract (the attributes and behaviour the GUI must provide; the tests rely on these
names)
------------------------------------------------------------------------------------------
``build_app() -> tuple[tk.Tk, App]`` creates the root and the App and returns both without
entering the main loop. It must let ``tkinter.TclError`` propagate when no display exists.

Root window:
    title ``"EncrypTOR"``; ``root.minsize()`` returns ``(720, 540)``.

Public attributes of ``App`` (Encrypt/Decrypt tab unless noted):
    root              tk.Tk           the root passed to ``App(root)``
    notebook          ttk.Notebook    exactly two tabs: index 0 Encrypt/Decrypt (selected
                                      at start-up), index 1 Crack demo
    action_var        tk.StringVar    ``"encrypt"`` (default) or ``"decrypt"``
    mode_var          tk.StringVar    ``"secure"`` (default) or ``"classic"``
    decimal_var       tk.BooleanVar   default False
    decimal_check     ttk.Checkbutton bound to ``decimal_var``
    banner            ttk.Label       text ``controller.CLASSIC_BANNER``; managed with
                                      ``grid()`` / ``grid_remove()``
    passphrase_entry  ttk.Entry       masked with ``show="*"``
    show_var          tk.BooleanVar   default False; True unmasks the entry (``show=""``)
    keep_var          tk.BooleanVar   default False; "Keep passphrase"
    input_text        tk.Text         editable
    output_text       tk.Text         read-only (``state="disabled"``) except while the
                                      app itself writes to it
    run_button        ttk.Button      Run on the Encrypt/Decrypt tab; disabled while busy

Variables are the interface: the App reacts to *writes* to ``mode_var`` and ``show_var``
(``trace_add("write", ...)``), not only to clicks, so ``app.mode_var.set("classic")`` must
show the banner and enable the decimal check, and ``app.mode_var.set("secure")`` must hide
the banner, disable the decimal check and reset ``decimal_var`` to False. Likewise
``app.show_var.set(True)`` must set the entry's ``show`` option to ``""``.

Public methods and properties of ``App``:
    run() -> None     start the operation of the selected tab on a worker job (what the
                      Run button and Ctrl+Enter do). Must return immediately; never
                      blocks on the cipher.
    clear() -> None   clear the selected tab (what the Clear button and Ctrl+L do). On
                      the Encrypt/Decrypt tab: empties input, output and the passphrase
                      entry, even when ``keep_var`` is True.
    busy -> bool      property; True from ``run()`` until the job's ``Done``/``Failed``
                      event has been applied to the widgets by the ``root.after`` poll.

The text widgets are read with ``get("1.0", "end-1c")``; the app must not leave a stray
trailing newline in ``output_text`` and must not pass the widget's implicit final newline
to the controller as part of the plaintext.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterator

import pytest

tkinter = pytest.importorskip("tkinter")

# isort: off
# Pinned for the same reason as in test_gui_controller.py: the sort order of
# ``encryptor.gui`` must not depend on whether the package exists yet.
from encryptor import classic  # noqa: E402
from encryptor.gui import app as gui_app  # noqa: E402
from encryptor.gui import controller  # noqa: E402

# isort: on

SMALL_BOUND = 4096
DEADLINE_SECONDS = 30.0
PASSPHRASE = "zebra quilt"
TEXT = "hello, world"


@pytest.fixture(autouse=True)
def small_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(classic, "OFFSET_BOUND", SMALL_BOUND)


@pytest.fixture
def window() -> Iterator[tuple[tkinter.Tk, gui_app.App]]:
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


def text_of(widget: tkinter.Text) -> str:
    return str(widget.get("1.0", "end-1c"))


def is_shown(root: tkinter.Tk, widget: tkinter.Widget) -> bool:
    """True if ``widget`` is under a geometry manager (``grid_remove`` clears it).

    This does not depend on the window actually being on screen, unlike
    ``winfo_ismapped``, so it also holds when the window is minimised or covered.
    """
    root.update()
    return str(widget.winfo_manager()) != ""


def is_disabled(widget: tkinter.Widget) -> bool:
    return bool(widget.instate(["disabled"]))  # type: ignore[attr-defined]


def wait_until_idle(root: tkinter.Tk, app: gui_app.App) -> None:
    """Pump the Tk event loop until the running job has been delivered to the widgets."""
    deadline = time.monotonic() + DEADLINE_SECONDS
    while app.busy:
        if time.monotonic() > deadline:
            pytest.fail(f"the operation did not finish within {DEADLINE_SECONDS} s")
        root.update()
        time.sleep(0.005)
    root.update()


def set_output(app: gui_app.App, text: str) -> None:
    app.output_text.configure(state="normal")
    app.output_text.insert("1.0", text)
    app.output_text.configure(state="disabled")


# ------------------------------------------------------------------------------- window


def test_window_builds_with_two_tabs_and_minimum_size(
    window: tuple[tkinter.Tk, gui_app.App],
) -> None:
    root, app = window
    assert isinstance(app, gui_app.App)
    assert app.root is root
    assert root.title() == "EncrypTOR"
    assert tuple(root.minsize()) == (720, 540)
    tabs = app.notebook.tabs()
    assert len(tabs) == 2
    assert app.notebook.index(app.notebook.select()) == 0


def test_defaults(window: tuple[tkinter.Tk, gui_app.App]) -> None:
    _, app = window
    assert app.action_var.get() == "encrypt"
    assert app.mode_var.get() == "secure"
    assert app.decimal_var.get() is False
    assert app.show_var.get() is False
    assert app.keep_var.get() is False
    assert app.passphrase_entry.get() == ""
    assert text_of(app.input_text) == ""
    assert text_of(app.output_text) == ""
    assert str(app.output_text.cget("state")) == "disabled"
    assert app.busy is False
    assert not is_disabled(app.run_button)


# --------------------------------------------------------------------------- passphrase


def test_passphrase_entry_is_masked_and_show_toggle_unmasks_it(
    window: tuple[tkinter.Tk, gui_app.App],
) -> None:
    root, app = window
    assert str(app.passphrase_entry.cget("show")) == "*"
    app.show_var.set(True)
    root.update()
    assert str(app.passphrase_entry.cget("show")) == ""
    app.show_var.set(False)
    root.update()
    assert str(app.passphrase_entry.cget("show")) == "*"


# ------------------------------------------------------------------- banner and decimal


def test_banner_is_shown_in_classic_mode_and_hidden_in_secure_mode(
    window: tuple[tkinter.Tk, gui_app.App],
) -> None:
    root, app = window
    assert str(app.banner.cget("text")) == controller.CLASSIC_BANNER
    assert "NOT secure" in str(app.banner.cget("text"))
    assert not is_shown(root, app.banner)  # secure is the default
    app.mode_var.set("classic")
    assert is_shown(root, app.banner)
    # It stays for as long as classic is selected, whatever else changes.
    app.action_var.set("decrypt")
    app.decimal_var.set(True)
    assert is_shown(root, app.banner)
    app.mode_var.set("secure")
    assert not is_shown(root, app.banner)
    app.mode_var.set("classic")
    assert is_shown(root, app.banner)


def test_decimal_is_disabled_and_unchecked_in_secure_mode(
    window: tuple[tkinter.Tk, gui_app.App],
) -> None:
    root, app = window
    root.update()
    assert is_disabled(app.decimal_check)
    assert app.decimal_var.get() is False
    app.mode_var.set("classic")
    root.update()
    assert not is_disabled(app.decimal_check)
    app.decimal_var.set(True)
    app.mode_var.set("secure")
    root.update()
    assert is_disabled(app.decimal_check)
    assert app.decimal_var.get() is False


# -------------------------------------------------------------------------------- clear


@pytest.mark.parametrize("keep", [False, True], ids=["keep-off", "keep-on"])
def test_clear_empties_input_output_and_passphrase(
    window: tuple[tkinter.Tk, gui_app.App], keep: bool
) -> None:
    root, app = window
    app.keep_var.set(keep)
    app.input_text.insert("1.0", "some input")
    app.passphrase_entry.insert(0, PASSPHRASE)
    set_output(app, "some output")
    root.update()
    assert text_of(app.output_text) == "some output"

    app.clear()
    root.update()
    assert text_of(app.input_text) == ""
    assert text_of(app.output_text) == ""
    assert app.passphrase_entry.get() == ""
    assert str(app.output_text.cget("state")) == "disabled"


# ---------------------------------------------------------------- run through the app


def run_classic_encrypt(root: tkinter.Tk, app: gui_app.App) -> None:
    app.mode_var.set("classic")
    app.action_var.set("encrypt")
    app.input_text.insert("1.0", TEXT)
    app.passphrase_entry.insert(0, PASSPHRASE)
    root.update()
    app.run()
    # run() only starts the worker job; the result arrives through the after-poll.
    assert app.busy is True
    assert text_of(app.output_text) == ""
    wait_until_idle(root, app)


def test_classic_encrypt_fills_output_and_clears_the_passphrase(
    window: tuple[tkinter.Tk, gui_app.App],
) -> None:
    root, app = window
    run_classic_encrypt(root, app)
    expected = classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE).hex()
    assert text_of(app.output_text) == expected
    assert app.passphrase_entry.get() == ""
    assert text_of(app.input_text) == TEXT
    assert str(app.output_text.cget("state")) == "disabled"
    assert app.busy is False
    assert not is_disabled(app.run_button)
    assert is_shown(root, app.banner)


def test_classic_encrypt_keeps_the_passphrase_when_keep_is_checked(
    window: tuple[tkinter.Tk, gui_app.App],
) -> None:
    root, app = window
    app.keep_var.set(True)
    run_classic_encrypt(root, app)
    assert text_of(app.output_text) == classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE).hex()
    assert app.passphrase_entry.get() == PASSPHRASE
    # Still masked: keeping the passphrase must not reveal it.
    assert str(app.passphrase_entry.cget("show")) == "*"


def test_classic_decimal_round_trip_through_the_app(
    window: tuple[tkinter.Tk, gui_app.App],
) -> None:
    root, app = window
    app.keep_var.set(True)
    app.mode_var.set("classic")
    app.decimal_var.set(True)
    app.input_text.insert("1.0", TEXT)
    app.passphrase_entry.insert(0, PASSPHRASE)
    app.run()
    wait_until_idle(root, app)
    encrypted = text_of(app.output_text)
    assert encrypted == " ".join(map(str, classic.encrypt(TEXT.encode("utf-8"), PASSPHRASE)))

    app.input_text.delete("1.0", "end")
    app.input_text.insert("1.0", encrypted)
    app.action_var.set("decrypt")
    app.run()
    wait_until_idle(root, app)
    assert text_of(app.output_text) == TEXT
