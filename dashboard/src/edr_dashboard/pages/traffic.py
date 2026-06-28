from __future__ import annotations

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.pages.live_helpers import REFRESH_MS, render_table, signature, source_label


class TrafficAnalyticsPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Traffic Analytics", "Traffic samples from network telemetry")
        self.service = service
        self._rows_signature = ""

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        source_label(body, 0)
        section = Section(body, "Traffic samples")
        section.grid(row=2, column=0, sticky="nsew")
        section.grid_rowconfigure(1, weight=1)
        self.table_host = ctk.CTkFrame(section, fg_color="transparent")
        self.table_host.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.table_host.grid_columnconfigure(0, weight=1)
        self.refresh_live()

    def refresh_live(self) -> None:
        rows = self.service.get_traffic_logs()
        rows_sig = signature(rows)
        if rows_sig != self._rows_signature:
            render_table(
                self.table_host,
                ["Time", "Device", "Event Type", "Source", "Destination", "Bytes", "Basis"],
                rows,
                [2, 2, 2, 2, 2, 1, 2],
                "No traffic telemetry available yet.",
            )
            self._rows_signature = rows_sig
        self.after(REFRESH_MS, self.refresh_live)
