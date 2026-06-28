from __future__ import annotations

import tkinter as tk
from typing import Any


_BOUND_TARGETS: dict[int, dict[str, str]] = {}
_ACTIVE_WIDGET_ID: int | None = None


def _scroll_units(delta: int) -> int:
    if delta == 0:
        return 0
    units = max(1, abs(delta) // 120)
    return -units if delta > 0 else units


def _is_shift_pressed(event) -> bool:
    return bool(event.state & 0x0001)


def _scroll_target(event, target) -> str:
    horizontal = _is_shift_pressed(event)
    button = getattr(event, "num", None)
    if button == 4:
        if horizontal:
            target.xview_scroll(-1, "units")
        else:
            target.yview_scroll(-1, "units")
        return "break"
    if button == 5:
        if horizontal:
            target.xview_scroll(1, "units")
        else:
            target.yview_scroll(1, "units")
        return "break"

    units = _scroll_units(int(getattr(event, "delta", 0)))
    if units:
        if horizontal:
            target.xview_scroll(units, "units")
        else:
            target.yview_scroll(units, "units")
    return "break"


def bind_mousewheel(widget, target) -> None:
    global _ACTIVE_WIDGET_ID
    root = widget.winfo_toplevel()
    key = id(widget)
    if _ACTIVE_WIDGET_ID == key and key in _BOUND_TARGETS:
        return
    if _ACTIVE_WIDGET_ID is not None:
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            root.unbind_all(sequence)
        _BOUND_TARGETS.clear()
    callbacks = {
        "<MouseWheel>": root.bind_all("<MouseWheel>", lambda event: _scroll_target(event, target), add="+"),
        "<Button-4>": root.bind_all("<Button-4>", lambda event: _scroll_target(event, target), add="+"),
        "<Button-5>": root.bind_all("<Button-5>", lambda event: _scroll_target(event, target), add="+"),
    }
    _BOUND_TARGETS[key] = callbacks
    _ACTIVE_WIDGET_ID = key


def unbind_mousewheel(widget) -> None:
    global _ACTIVE_WIDGET_ID
    root = widget.winfo_toplevel()
    if _ACTIVE_WIDGET_ID != id(widget):
        return
    callbacks = _BOUND_TARGETS.pop(id(widget), None)
    if not callbacks:
        _ACTIVE_WIDGET_ID = None
        return
    for sequence in callbacks:
        root.unbind_all(sequence)
    _ACTIVE_WIDGET_ID = None


def _contains(root_widget, candidate) -> bool:
    while candidate is not None:
        if candidate == root_widget:
            return True
        candidate = getattr(candidate, "master", None)
    return False


def _bind_hover_recursive(widget, enter, leave) -> None:
    widget.bind("<Enter>", enter, add="+")
    widget.bind("<Leave>", leave, add="+")
    for child in widget.winfo_children():
        _bind_hover_recursive(child, enter, leave)


def enable_frame_scrolling(frame, canvas) -> None:
    def enter(_event=None) -> None:
        bind_mousewheel(frame, canvas)

    def leave(_event=None) -> None:
        def maybe_unbind() -> None:
            x = frame.winfo_pointerx()
            y = frame.winfo_pointery()
            current = frame.winfo_containing(x, y)
            if not _contains(frame, current):
                unbind_mousewheel(frame)

        frame.after(20, maybe_unbind)

    _bind_hover_recursive(frame, enter, leave)


def enable_treeview_scrolling(treeview) -> None:
    enable_frame_scrolling(treeview, treeview)


def update_table_if_changed(table: Any, new_rows: list[dict]) -> bool:
    if hasattr(table, "update_rows_if_changed"):
        return bool(table.update_rows_if_changed(new_rows))
    return True
