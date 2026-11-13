"""Dark ttk theme for the GUI: one palette of named colours and the style setup."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Final

BG: Final[str] = "#1e1f24"
SURFACE: Final[str] = "#2a2c33"
FIELD: Final[str] = "#15161a"
FG: Final[str] = "#e6e6e6"
MUTED: Final[str] = "#9aa0aa"
ACCENT: Final[str] = "#4f8cff"
ACCENT_ACTIVE: Final[str] = "#6a9fff"
WARNING_BG: Final[str] = "#5a3a0a"
WARNING_FG: Final[str] = "#ffd27a"
DISABLED_FG: Final[str] = "#666a73"
SELECT_BG: Final[str] = "#3a5a9a"


def apply_dark_theme(root: tk.Tk) -> ttk.Style:
    """Switch ttk to the "clam" theme and recolour it dark. Time O(1)."""
    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(background=BG)
    style.configure(".", background=BG, foreground=FG, fieldbackground=FIELD, bordercolor=SURFACE)
    style.map(".", foreground=[("disabled", DISABLED_FG)])
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Muted.TLabel", foreground=MUTED)
    style.configure(
        "Banner.TLabel", background=WARNING_BG, foreground=WARNING_FG, padding=(8, 4)
    )
    style.configure("TButton", background=SURFACE, foreground=FG, padding=(10, 4))
    style.map(
        "TButton",
        background=[("disabled", BG), ("pressed", ACCENT), ("active", ACCENT_ACTIVE)],
        foreground=[("disabled", DISABLED_FG)],
    )
    for widget in ("TCheckbutton", "TRadiobutton"):
        style.configure(widget, background=BG, foreground=FG, indicatorbackground=FIELD)
        style.map(
            widget,
            background=[("active", BG)],
            indicatorbackground=[("selected", ACCENT)],
            foreground=[("disabled", DISABLED_FG)],
        )
    style.configure("TEntry", fieldbackground=FIELD, foreground=FG, insertcolor=FG)
    style.configure("TNotebook", background=BG, bordercolor=SURFACE)
    style.configure("TNotebook.Tab", background=SURFACE, foreground=MUTED, padding=(12, 4))
    style.map(
        "TNotebook.Tab",
        background=[("selected", BG)],
        foreground=[("selected", FG)],
    )
    style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=FIELD)
    style.configure("Vertical.TScrollbar", background=SURFACE, troughcolor=BG, arrowcolor=FG)
    return style


def style_text(widget: tk.Text) -> None:
    """Colour a plain ``tk.Text`` to match the theme. Time O(1)."""
    widget.configure(
        background=FIELD,
        foreground=FG,
        insertbackground=FG,
        selectbackground=SELECT_BG,
        selectforeground=FG,
        relief="flat",
        highlightthickness=1,
        highlightbackground=SURFACE,
        highlightcolor=ACCENT,
    )
