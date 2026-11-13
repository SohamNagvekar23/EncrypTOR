"""Tkinter widgets for the EncrypTOR GUI. All logic lives in ``controller``.

The UI thread never runs a cipher or a search: ``run`` starts a ``controller.Job`` on a
worker thread and a ``root.after`` loop drains its events. The passphrase lives only in
the masked entry and in the request handed to the worker; it is never logged, shown in
a dialog or status line, written to disk or put on the clipboard.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import messagebox, ttk
from types import TracebackType
from typing import Final

from encryptor import EncryptorError, classic
from encryptor.crack import CrackResult
from encryptor.gui import controller
from encryptor.gui.theme import apply_dark_theme, style_text

TITLE: Final[str] = "EncrypTOR"
MIN_SIZE: Final[tuple[int, int]] = (720, 540)
INITIAL_GEOMETRY: Final[str] = "860x620"
_IS_MAC: Final[bool] = sys.platform == "darwin"
_RUN_HINT: Final[str] = "Cmd+Enter" if _IS_MAC else "Ctrl+Enter"
_CLEAR_HINT: Final[str] = "Cmd+L" if _IS_MAC else "Ctrl+L"


def _scrolled_text(
    parent: ttk.Frame, height: int, *, undo: bool = True
) -> tuple[ttk.Frame, tk.Text]:
    """Return a frame holding a themed ``tk.Text`` with a vertical scrollbar.

    Read-only widgets pass ``undo=False``: the app replaces their whole content, and an
    undo stack would keep every old value (including plaintext) alive.
    """
    frame = ttk.Frame(parent)
    text = tk.Text(frame, height=height, wrap="char", undo=undo)
    style_text(text)
    bar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=bar.set)
    text.grid(row=0, column=0, sticky="nsew")
    bar.grid(row=0, column=1, sticky="ns")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    return frame, text


def _set_readonly_text(widget: tk.Text, value: str) -> None:
    """Replace the content of a read-only text widget. Time O(len(value))."""
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    if value:
        widget.insert("1.0", value)
    widget.configure(state="disabled")


def _replace_input(widget: tk.Text, value: str) -> None:
    """Replace an editable widget's text and drop its undo history.

    Without ``edit_reset`` Ctrl+Z would bring cleared or swapped-out text back, and the
    undo stack would keep it in memory. Time O(len(value)).
    """
    widget.delete("1.0", "end")
    if value:
        widget.insert("1.0", value)
    widget.edit_reset()


def _get_text(widget: tk.Text) -> str:
    """Return the widget's text without Tk's implicit trailing newline."""
    return str(widget.get("1.0", "end-1c"))


class App:
    """The main window: an Encrypt/Decrypt tab, a Crack demo tab and a status line."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title(TITLE)
        root.minsize(*MIN_SIZE)
        root.geometry(INITIAL_GEOMETRY)
        apply_dark_theme(root)
        root.report_callback_exception = self._report_callback_exception
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._cipher_job: controller.Job[str] | None = None
        # A cipher job dropped by Clear: its scrypt worker cannot be interrupted, so no
        # new cipher job starts until it ends (no stacking of ~128 MiB workers). Its
        # events are never polled, so its result is discarded.
        self._dropped_cipher_job: controller.Job[str] | None = None
        self._crack_job: controller.Job[CrackResult] | None = None
        self._after_id: str | None = None
        self._closed = False
        # The output as produced, before display wrapping; this is what Copy copies.
        self._output_raw = ""
        self._cipher_action: controller.Action = "encrypt"
        # Set by Cancel; a result that was already queued is then reported as cancelled.
        self._crack_cancel_requested = False

        outer = ttk.Frame(root, padding=8)
        outer.pack(fill="both", expand=True)
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(outer, textvariable=self.status_var, style="Muted.TLabel").pack(
            fill="x", pady=(6, 0)
        )

        self._build_cipher_tab()
        self._build_crack_tab()
        self._bind_shortcuts()
        self._on_mode_change()

    # ------------------------------------------------------------------ construction

    def _build_cipher_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Encrypt / Decrypt")
        tab.columnconfigure(0, weight=1)

        options = ttk.Frame(tab)
        options.grid(row=0, column=0, sticky="ew")
        self.action_var = tk.StringVar(value="encrypt")
        self.mode_var = tk.StringVar(value="secure")
        self.decimal_var = tk.BooleanVar(value=False)
        ttk.Label(options, text="Action:").pack(side="left")
        for label, value in (("Encrypt", "encrypt"), ("Decrypt", "decrypt")):
            ttk.Radiobutton(options, text=label, value=value, variable=self.action_var).pack(
                side="left", padx=(4, 0)
            )
        ttk.Label(options, text="Mode:").pack(side="left", padx=(16, 0))
        for label, value in (("Secure", "secure"), ("Classic", "classic")):
            ttk.Radiobutton(options, text=label, value=value, variable=self.mode_var).pack(
                side="left", padx=(4, 0)
            )
        self.decimal_check = ttk.Checkbutton(
            options, text="Decimal output/input (classic only)", variable=self.decimal_var
        )
        self.decimal_check.pack(side="left", padx=(16, 0))
        self.mode_var.trace_add("write", lambda *_: self._on_mode_change())

        self.banner = ttk.Label(tab, text=controller.CLASSIC_BANNER, style="Banner.TLabel")
        self.banner.grid(row=1, column=0, sticky="ew", pady=(8, 0))

        secret = ttk.Frame(tab)
        secret.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        secret.columnconfigure(1, weight=1)
        ttk.Label(secret, text="Passphrase:").grid(row=0, column=0, sticky="w")
        # exportselection=False keeps an unmasked selection off the X11 PRIMARY
        # selection; <<Copy>> and <<Cut>> are blocked so it never reaches the clipboard.
        self.passphrase_entry = ttk.Entry(secret, show="*", exportselection=False)
        self.passphrase_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        for sequence in ("<<Copy>>", "<<Cut>>"):
            self.passphrase_entry.bind(sequence, lambda _event: "break")
        self.show_var = tk.BooleanVar(value=False)
        self.keep_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(secret, text="Show", variable=self.show_var).grid(
            row=0, column=2, padx=(8, 0)
        )
        ttk.Checkbutton(secret, text="Keep passphrase", variable=self.keep_var).grid(
            row=0, column=3, padx=(8, 0)
        )
        self.show_var.trace_add("write", lambda *_: self._on_show_change())

        ttk.Label(tab, text="Input:").grid(row=3, column=0, sticky="w", pady=(8, 0))
        input_frame, self.input_text = _scrolled_text(tab, height=8)
        input_frame.grid(row=4, column=0, sticky="nsew")
        tab.rowconfigure(4, weight=1)

        buttons = ttk.Frame(tab)
        buttons.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        self.run_button = ttk.Button(buttons, text=f"Run ({_RUN_HINT})", command=self.run)
        self.run_button.pack(side="left")
        ttk.Button(buttons, text="Swap output into input", command=self.swap).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(buttons, text=f"Clear ({_CLEAR_HINT})", command=self.clear).pack(
            side="left", padx=(6, 0)
        )
        self.cipher_progress = ttk.Progressbar(buttons, mode="indeterminate", length=160)
        self.cipher_progress.pack(side="right")

        out_header = ttk.Frame(tab)
        out_header.grid(row=6, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(out_header, text="Output:").pack(side="left")
        ttk.Button(out_header, text="Copy", command=self.copy_output).pack(side="right")
        output_frame, self.output_text = _scrolled_text(tab, height=8, undo=False)
        # exportselection=False keeps selected output (plaintext after a decrypt) off
        # the X11 PRIMARY selection; Copy is the explicit way out.
        self.output_text.configure(state="disabled", exportselection=False)
        output_frame.grid(row=7, column=0, sticky="nsew")
        tab.rowconfigure(7, weight=1)

    def _build_crack_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Crack demo")
        self._crack_tab = tab
        tab.columnconfigure(0, weight=1)

        ttk.Label(tab, text=controller.CLASSIC_BANNER, style="Banner.TLabel").grid(
            row=0, column=0, sticky="ew"
        )
        ttk.Label(tab, text="Known plaintext:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        plain_frame, self.crack_plain_text = _scrolled_text(tab, height=3)
        plain_frame.grid(row=2, column=0, sticky="nsew")
        ttk.Label(tab, text="Its classic-mode ciphertext (hex):").grid(
            row=3, column=0, sticky="w", pady=(8, 0)
        )
        cipher_frame, self.crack_cipher_text = _scrolled_text(tab, height=3)
        cipher_frame.grid(row=4, column=0, sticky="nsew")
        tab.rowconfigure(2, weight=1)
        tab.rowconfigure(4, weight=1)

        limit_row = ttk.Frame(tab)
        limit_row.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(limit_row, text="Max offset:").pack(side="left")
        self.max_offset_entry = ttk.Entry(limit_row, width=12)
        self.max_offset_entry.pack(side="left", padx=(6, 0))
        ttk.Label(
            limit_row,
            text=f"blank = full range ({classic.OFFSET_BOUND})",
            style="Muted.TLabel",
        ).pack(side="left", padx=(8, 0))

        buttons = ttk.Frame(tab)
        buttons.grid(row=6, column=0, sticky="ew", pady=(8, 0))
        self.crack_run_button = ttk.Button(
            buttons, text=f"Run ({_RUN_HINT})", command=self.run
        )
        self.crack_run_button.pack(side="left")
        self.cancel_button = ttk.Button(
            buttons, text="Cancel", command=self.cancel_crack, state="disabled"
        )
        self.cancel_button.pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text=f"Clear ({_CLEAR_HINT})", command=self.clear).pack(
            side="left", padx=(6, 0)
        )

        self.crack_progress = ttk.Progressbar(tab, mode="determinate", maximum=100.0)
        self.crack_progress.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        self.crack_progress_var = tk.StringVar(value="")
        ttk.Label(tab, textvariable=self.crack_progress_var, style="Muted.TLabel").grid(
            row=8, column=0, sticky="w"
        )
        ttk.Label(tab, text="Result:").grid(row=9, column=0, sticky="w", pady=(8, 0))
        self.crack_result_text = tk.Text(tab, height=3, wrap="word", undo=False)
        style_text(self.crack_result_text)
        self.crack_result_text.configure(state="disabled")
        self.crack_result_text.grid(row=10, column=0, sticky="ew")

    def _bind_shortcuts(self) -> None:
        run_keys = ["<Control-Return>", "<Control-KP_Enter>"]
        clear_keys = ["<Control-l>", "<Control-L>"]
        if _IS_MAC:
            run_keys.append("<Command-Return>")
            clear_keys.append("<Command-l>")
        for key in run_keys:
            self.root.bind_all(key, self._on_run_key)
            # The Text class binding for <Return> also matches Ctrl+Return and would
            # insert a newline (or replace the selection) before the "all" binding runs.
            # A widget-level binding that returns "break" runs first and stops both, so
            # run() fires exactly once and the text is left unchanged.
            for widget in (self.input_text, self.crack_plain_text, self.crack_cipher_text):
                widget.bind(key, self._on_run_key)
        for key in clear_keys:
            self.root.bind_all(key, self._on_clear_key)

    # --------------------------------------------------------------------- reactions

    def _on_run_key(self, _event: tk.Event[tk.Misc]) -> str:
        self.run()
        return "break"

    def _on_clear_key(self, _event: tk.Event[tk.Misc]) -> str:
        self.clear()
        return "break"

    def _on_mode_change(self) -> None:
        if self.mode_var.get() == "classic":
            self.banner.grid()
            self.decimal_check.state(["!disabled"])
        else:
            self.banner.grid_remove()
            self.decimal_var.set(False)
            self.decimal_check.state(["disabled"])

    def _on_show_change(self) -> None:
        self.passphrase_entry.configure(show="" if self.show_var.get() else "*")

    def _mask_passphrase(self) -> None:
        """Turn the Show toggle off; the trace re-masks the entry."""
        self.show_var.set(False)
        self.passphrase_entry.configure(show="*")

    def _on_crack_tab(self) -> bool:
        selected: str = str(self.notebook.select())  # type: ignore[no-untyped-call]
        return selected == str(self._crack_tab)

    @property
    def busy(self) -> bool:
        """True from ``run()`` until the job's final event has been applied."""
        return self._cipher_job is not None or self._crack_job is not None

    def _set_busy(self, busy: bool) -> None:
        state = ["disabled"] if busy else ["!disabled"]
        self.run_button.state(state)
        self.crack_run_button.state(state)

    # ----------------------------------------------------------------------- actions

    def run(self) -> None:
        """Start the selected tab's operation on a worker job; returns immediately."""
        if self.busy:
            return
        if self._on_crack_tab():
            self._start_crack()
        else:
            self._start_cipher()

    def _start_cipher(self) -> None:
        if self._dropped_cipher_job is not None:
            if self._dropped_cipher_job.running:
                # The passphrase stays in the field so the user can simply run again.
                self.status_var.set("Previous operation still finishing...")
                return
            self._dropped_cipher_job = None
        mode: controller.Mode = "classic" if self.mode_var.get() == "classic" else "secure"
        action: controller.Action = (
            "decrypt" if self.action_var.get() == "decrypt" else "encrypt"
        )
        self._mask_passphrase()
        request = controller.CipherRequest(
            action=action,
            mode=mode,
            text=_get_text(self.input_text),
            passphrase=self.passphrase_entry.get(),
            decimal=bool(self.decimal_var.get()) and mode == "classic",
        )
        # Cheap checks run here, before the passphrase is cleared, so a typo in the
        # input does not cost the user their passphrase. scrypt and BBP stay on the worker.
        try:
            payload = controller.prepare_cipher(request)
        except EncryptorError as error:
            del request
            self._show_error(controller.describe_error(error))
            return
        if not self.keep_var.get():
            self.passphrase_entry.delete(0, "end")
        self._set_output("")
        self._cipher_action = action
        self._cipher_job = controller.start_cipher(request, payload)
        del request, payload
        self._set_busy(True)
        self.cipher_progress.start(15)
        self.status_var.set("Working...")
        self._schedule_poll()

    def _start_crack(self) -> None:
        try:
            max_offset = controller.parse_max_offset(self.max_offset_entry.get())
        except EncryptorError as error:
            self._show_error(controller.describe_error(error))
            return
        request = controller.CrackRequest(
            plaintext=_get_text(self.crack_plain_text),
            ciphertext_hex=_get_text(self.crack_cipher_text),
            max_offset=max_offset,
        )
        _set_readonly_text(self.crack_result_text, "")
        self.crack_progress.configure(value=0.0)
        self.crack_progress_var.set("")
        self._crack_cancel_requested = False
        self._mask_passphrase()
        self._crack_job = controller.start_crack(request)
        self._set_busy(True)
        self.cancel_button.state(["!disabled"])
        self.status_var.set("Searching...")
        self._schedule_poll()

    def cancel_crack(self) -> None:
        """Ask the running crack to stop; it does so within one digit chunk (about 1 s)."""
        if self._crack_job is not None:
            self._crack_job.cancel()
            self._crack_cancel_requested = True
            self.cancel_button.state(["disabled"])
            self.status_var.set("Cancelling...")

    def clear(self) -> None:
        """Clear the selected tab; on Encrypt/Decrypt this always clears the passphrase.

        Clearing Encrypt/Decrypt also drops a running cipher job: the worker cannot be
        interrupted (scrypt), but its result is discarded and the tab returns to idle.
        A new cipher job is refused until the dropped worker has finished.
        """
        if self._on_crack_tab():
            for widget in (self.crack_plain_text, self.crack_cipher_text):
                _replace_input(widget, "")
            self.max_offset_entry.delete(0, "end")
            if self._crack_job is None:
                _set_readonly_text(self.crack_result_text, "")
                self.crack_progress.configure(value=0.0)
                self.crack_progress_var.set("")
            return
        if self._cipher_job is not None:
            self._cipher_job.cancel()
            self._dropped_cipher_job = self._cipher_job
            self._cipher_job = None
            self.cipher_progress.stop()
            self._set_busy(self.busy)  # a crack job may still be running
            self.status_var.set("Cleared.")
        _replace_input(self.input_text, "")
        self._set_output("")
        self.passphrase_entry.delete(0, "end")
        self._mask_passphrase()

    def swap(self) -> None:
        """Move the output into the input and clear the output.

        The displayed (wrapped) text is moved, so the input never holds one huge line;
        decrypt ignores the line breaks.
        """
        output = _get_text(self.output_text)
        if not output:
            return
        _replace_input(self.input_text, output)
        self._set_output("")

    def copy_output(self) -> None:
        """Copy the unwrapped output (never the passphrase) to the clipboard."""
        if self._output_raw:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._output_raw)
            self.status_var.set("Output copied to the clipboard.")

    def _set_output(self, raw: str, display: str | None = None) -> None:
        """Show ``display`` (default ``raw``) in the output and keep ``raw`` for Copy."""
        self._output_raw = raw
        _set_readonly_text(self.output_text, raw if display is None else display)

    # ----------------------------------------------------------------------- polling

    def _schedule_poll(self) -> None:
        if self._after_id is None and not self._closed:
            self._after_id = self.root.after(controller.POLL_INTERVAL_MS, self._poll)

    def _poll(self) -> None:
        """Apply queued job events, then reschedule while a job is live.

        If applying an event raises, the jobs whose events were drained can never
        report again, so they are dropped and the UI is made idle before the error
        reaches ``_report_callback_exception``. Time O(events).
        """
        self._after_id = None
        if self._closed:
            return
        try:
            if self._cipher_job is not None:
                for event in self._cipher_job.poll():
                    self._apply_cipher_event(event)
            if self._crack_job is not None:
                for crack_event in self._crack_job.poll():
                    self._apply_crack_event(crack_event)
        except BaseException:
            self._abandon_jobs()
            raise
        finally:
            if self.busy:
                self._schedule_poll()

    def _abandon_jobs(self) -> None:
        """Cancel and drop every job and return the widgets to the idle state."""
        for job in (self._cipher_job, self._crack_job):
            if job is not None:
                job.cancel()
        self._cipher_job = None
        self._crack_job = None
        if self._closed:
            return
        self.cipher_progress.stop()
        self._set_busy(False)
        self.cancel_button.state(["disabled"])
        self.status_var.set("Failed.")

    def _apply_cipher_event(self, event: controller.JobEvent[str]) -> None:
        if isinstance(event, controller.Progress):
            return
        self._cipher_job = None
        self.cipher_progress.stop()
        self._set_busy(False)
        if isinstance(event, controller.Done):
            self._set_output(
                event.value, controller.display_text(self._cipher_action, event.value)
            )
            self.status_var.set("Done.")
        else:
            self.status_var.set("Failed.")
            self._show_error(event.error)

    def _apply_crack_event(self, event: controller.JobEvent[CrackResult]) -> None:
        if isinstance(event, controller.Progress):
            item = event.value
            self.crack_progress.configure(value=item.fraction * 100.0)
            self.crack_progress_var.set(
                f"ruled out offsets below {item.searched} of {item.limit}"
            )
            return
        self._crack_job = None
        self._set_busy(False)
        self.cancel_button.state(["disabled"])
        if self._crack_cancel_requested and (
            isinstance(event, controller.Done) or event.not_found
        ):
            # The search ended on its own between the Cancel click and this poll; the
            # user asked to cancel, so report that rather than a late result.
            self.status_var.set("The search was cancelled.")
        elif isinstance(event, controller.Done):
            self.crack_progress.configure(value=100.0)
            _set_readonly_text(
                self.crack_result_text, controller.format_crack_result(event.value)
            )
            self.status_var.set("Offset recovered.")
        elif event.cancelled:
            self.status_var.set(event.error.message)
        elif event.not_found:
            _set_readonly_text(self.crack_result_text, event.error.message)
            self.status_var.set("Offset not found.")
        else:
            self.status_var.set("Failed.")
            self._show_error(event.error)

    # ------------------------------------------------------------------------ errors

    def _show_error(self, info: controller.ErrorInfo) -> None:
        if self._closed:
            return
        messagebox.showerror(info.title, info.message, parent=self.root)

    def _report_callback_exception(
        self,
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_traceback: TracebackType | None,
    ) -> None:
        if self._closed:
            return
        self._show_error(controller.describe_error(exc_value))

    def _on_close(self) -> None:
        """Cancel jobs and destroy the window; later callbacks become no-ops."""
        if self._closed:
            return
        self._closed = True
        for job in (self._cipher_job, self._crack_job):
            if job is not None:
                job.cancel()
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
            self._after_id = None
        self.cipher_progress.stop()  # its Tcl timer would fire on a destroyed widget
        self.root.destroy()


def build_app() -> tuple[tk.Tk, App]:
    """Create the root window and the App without entering the main loop.

    Raises ``tkinter.TclError`` when no display is available.
    """
    root = tk.Tk()
    return root, App(root)


def main() -> int:
    """Run the GUI until the window is closed. Returns the process exit code."""
    try:
        root, _app = build_app()
    except tk.TclError:
        print("encryptor: no display available", file=sys.stderr)
        return 1
    root.mainloop()
    return 0
