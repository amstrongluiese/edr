from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from edr_dashboard.scrolling import enable_frame_scrolling
from edr_dashboard.theme import COLORS, FONT_BODY, FONT_ICON, FONT_METRIC, FONT_SECTION, FONT_SMALL, FONT_TABLE


METRIC_ICONS = {
    "Total devices": "\u25a3",
    "Devices online": "\u25cf",
    "Unknown devices": "\u25b3",
    "Active connections": "\u21c4",
    "Threats today": "\u26a0",
    "Suspicious DNS": "\u25ce",
    "Incidents today": "\u25a0",
    "Overall risk": "\u25c8",
    "Discovered": "\u25a3",
    "Trusted": "\u2713",
    "Suspicious": "\u26a0",
}


class Page(ctk.CTkFrame):
    def __init__(self, master, title: str, subtitle: str) -> None:
        super().__init__(master, fg_color=COLORS["background"], corner_radius=0)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text=title,
            font=("Segoe UI", 22, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(
            header,
            text=subtitle,
            font=FONT_BODY,
            text_color=COLORS["muted"],
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(2, 0))


class Section(ctk.CTkFrame):
    def __init__(self, master, title: str) -> None:
        super().__init__(
            master,
            fg_color=COLORS["surface"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=6,
        )
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self,
            text=title,
            font=FONT_SECTION,
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 7))


class MetricCard(ctk.CTkFrame):
    def __init__(self, master, label: str, value: str, delta: str, tone: str) -> None:
        super().__init__(
            master,
            fg_color=COLORS["surface"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=6,
            height=72,
        )
        self.grid_propagate(False)
        self.grid_columnconfigure(1, weight=1)

        icon_frame = ctk.CTkFrame(self, width=34, height=34, corner_radius=8, fg_color=COLORS["accent_soft"])
        icon_frame.grid(row=0, column=0, rowspan=2, sticky="nw", padx=(12, 8), pady=10)
        icon_frame.grid_propagate(False)
        ctk.CTkLabel(
            icon_frame,
            text=METRIC_ICONS.get(label, "\u25a1"),
            font=FONT_ICON,
            text_color=COLORS[tone],
        ).grid(row=0, column=0, sticky="nsew")
        icon_frame.grid_columnconfigure(0, weight=1)
        icon_frame.grid_rowconfigure(0, weight=1)

        ctk.CTkLabel(self, text=value, font=FONT_METRIC, text_color=COLORS["text"], anchor="w").grid(
            row=0, column=1, sticky="ew", padx=(0, 12), pady=(8, 0)
        )
        ctk.CTkLabel(self, text=label, font=FONT_SMALL, text_color=COLORS["muted"], anchor="w").grid(
            row=1, column=1, sticky="ew", padx=(0, 12)
        )
        ctk.CTkLabel(self, text=delta, font=FONT_SMALL, text_color=COLORS[tone], anchor="w").grid(
            row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 8)
        )


class DataTable(ctk.CTkFrame):
    def __init__(
        self,
        master,
        columns: list[str],
        rows: list[dict],
        widths: list[int] | None = None,
        height: int = 260,
    ) -> None:
        super().__init__(master, fg_color=COLORS["surface"], height=height)
        self.grid_propagate(False)
        self._signature = repr(rows)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        widths = widths or [1 for _ in columns]
        column_widths = [max(96, weight * 90) for weight in widths]

        canvas = tk.Canvas(
            self,
            bg=COLORS["surface"],
            highlightthickness=0,
            bd=0,
            xscrollincrement=16,
            yscrollincrement=16,
        )
        v_scroll = ctk.CTkScrollbar(self, orientation="vertical", command=canvas.yview, width=12)
        h_scroll = ctk.CTkScrollbar(self, orientation="horizontal", command=canvas.xview, height=12)
        canvas.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns", padx=(4, 0))
        h_scroll.grid(row=1, column=0, sticky="ew", pady=(4, 0))

        inner = ctk.CTkFrame(canvas, fg_color=COLORS["surface"])
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        for index, width in enumerate(column_widths):
            inner.grid_columnconfigure(index, minsize=width)

        for col, title in enumerate(columns):
            ctk.CTkLabel(
                inner,
                text=title,
                font=FONT_SMALL,
                text_color=COLORS["muted"],
                fg_color=COLORS["table_header"],
                anchor="w",
                height=28,
            ).grid(row=0, column=col, sticky="ew", padx=(0, 1), pady=(0, 1))

        for row_index, row in enumerate(rows, start=1):
            bg = COLORS["surface_alt"] if row_index % 2 else COLORS["surface"]
            for col_index, column in enumerate(columns):
                value = str(row.get(column.lower().replace(" ", "_"), row.get(column.lower(), "")))
                ctk.CTkLabel(
                    inner,
                    text=value,
                    font=FONT_TABLE,
                    text_color=COLORS["text"],
                    fg_color=bg,
                    anchor="w",
                    height=30,
                    corner_radius=0,
                    wraplength=max(84, column_widths[col_index] - 16),
                    justify="left",
                ).grid(row=row_index, column=col_index, sticky="ew", padx=(0, 1), pady=(0, 1))

        def update_scrollregion(_event=None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_canvas(event) -> None:
            content_width = max(sum(column_widths) + len(columns), event.width)
            canvas.itemconfigure(window_id, width=content_width)

        def wheel(event) -> None:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        inner.bind("<Configure>", update_scrollregion)
        canvas.bind("<Configure>", resize_canvas)
        enable_frame_scrolling(self, canvas)

    def update_rows_if_changed(self, new_rows: list[dict]) -> bool:
        signature = repr(new_rows)
        if signature == self._signature:
            return False
        self._signature = signature
        return True
