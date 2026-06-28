from __future__ import annotations

import json

import customtkinter as ctk

from edr_dashboard.components import DataTable, MetricCard
from edr_dashboard.live_data import DATA_SOURCE_LABEL
from edr_dashboard.scrolling import update_table_if_changed
from edr_dashboard.theme import COLORS, FONT_BODY, FONT_SMALL


REFRESH_MS = 2500
MAX_TABLE_ROWS = 150


def signature(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def source_label(master, row: int = 0) -> ctk.CTkLabel:
    label = ctk.CTkLabel(master, text=DATA_SOURCE_LABEL, font=FONT_SMALL, text_color=COLORS["muted"], anchor="w")
    label.grid(row=row, column=0, sticky="ew", pady=(0, 6))
    return label


def empty_state(master, text: str) -> None:
    frame = ctk.CTkFrame(master, fg_color=COLORS["surface_alt"], border_color=COLORS["border"], border_width=1, corner_radius=6)
    frame.grid(row=0, column=0, sticky="nsew")
    frame.grid_columnconfigure(0, weight=1)
    ctk.CTkLabel(
        frame,
        text=text,
        font=FONT_BODY,
        text_color=COLORS["muted"],
        anchor="center",
        height=80,
    ).grid(row=0, column=0, sticky="nsew", padx=12, pady=12)


def render_table(master, columns: list[str], rows: list[dict], widths: list[int], empty_text: str) -> None:
    rows = rows[:MAX_TABLE_ROWS]
    previous_table = getattr(master, "_data_table", None)
    if previous_table is not None and update_table_if_changed(previous_table, rows) is False:
        return
    for child in master.winfo_children():
        child.destroy()
    master._data_table = None
    if not rows:
        empty_state(master, empty_text)
        return
    master.grid_rowconfigure(0, weight=1)
    master.grid_columnconfigure(0, weight=1)
    table = DataTable(master, columns, rows, widths)
    table.grid(row=0, column=0, sticky="nsew")
    master._data_table = table


def render_metrics(master, metrics: list[dict], columns: int = 4) -> None:
    for child in master.winfo_children():
        child.destroy()
    master.grid_columnconfigure(tuple(range(columns)), weight=1)
    for index, metric in enumerate(metrics):
        row = index // columns
        column = index % columns
        MetricCard(master, **metric).grid(
            row=row,
            column=column,
            sticky="ew",
            padx=(0 if column == 0 else 12, 0),
            pady=(0, 8),
        )


def debug_panel(master, service, row: int) -> ctk.CTkFrame:
    panel = ctk.CTkFrame(master, fg_color=COLORS["surface"], border_color=COLORS["border"], border_width=1, corner_radius=6)
    panel.grid(row=row, column=0, sticky="ew", pady=(8, 0))
    panel.grid_columnconfigure(tuple(range(7)), weight=1)
    labels: dict[str, ctk.CTkLabel] = {}
    keys = [
        ("sensor_status", "Sensor"),
        ("database_status", "Database"),
        ("last_telemetry_received", "Last telemetry"),
        ("last_dashboard_refresh", "Last refresh"),
        ("rows_loaded", "Rows loaded"),
        ("status", "Status"),
        ("uptime", "Uptime"),
    ]
    for column, (key, title) in enumerate(keys):
        ctk.CTkLabel(panel, text=title, font=FONT_SMALL, text_color=COLORS["muted"], anchor="w").grid(
            row=0, column=column, sticky="ew", padx=10, pady=(8, 0)
        )
        label = ctk.CTkLabel(panel, text="", font=FONT_BODY, text_color=COLORS["text"], anchor="w")
        label.grid(row=1, column=column, sticky="ew", padx=10, pady=(1, 8))
        labels[key] = label

    def update() -> None:
        status = service.get_debug_status()
        status.setdefault("status", "Healthy" if status.get("database_status") == "Connected" else "Warning")
        status.setdefault("uptime", "Current session")
        for key, label in labels.items():
            label.configure(text=str(status.get(key, "")))
        panel.after(REFRESH_MS, update)

    update()
    return panel
