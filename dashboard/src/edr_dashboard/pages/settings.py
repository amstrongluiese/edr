from __future__ import annotations

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.theme import COLORS, FONT_BODY, FONT_SECTION


class SettingsPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Settings", "Console preferences and live telemetry configuration")
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure((0, 1), weight=1)

        appearance = Section(body, "Appearance")
        appearance.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self._setting_row(appearance, 1, "Theme", "Light enterprise")
        self._setting_row(appearance, 2, "Density", "Comfortable")
        self._setting_row(appearance, 3, "Refresh interval", "2.5 seconds")

        operations = Section(body, "Operations")
        operations.grid(row=0, column=1, sticky="nsew")
        self._setting_row(operations, 1, "Data source", "Live SQLite / Sensor Telemetry")
        self._setting_row(operations, 2, "Telemetry mode", "Read only")
        self._setting_row(operations, 3, "Report exports", "Local folder")

    def _setting_row(self, master, row: int, label: str, value: str) -> None:
        frame = ctk.CTkFrame(master, fg_color=COLORS["surface_alt"], corner_radius=8)
        frame.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text=label, font=FONT_SECTION, text_color=COLORS["text"], anchor="w").grid(
            row=0, column=0, sticky="ew", padx=14, pady=(10, 0)
        )
        ctk.CTkLabel(frame, text=value, font=FONT_BODY, text_color=COLORS["muted"], anchor="w").grid(
            row=1, column=0, sticky="ew", padx=14, pady=(2, 10)
        )
