from __future__ import annotations

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.pages.live_helpers import REFRESH_MS, render_table, signature, source_label


class ConnectionsPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Connections", "Live network connection events from sensor telemetry")
        self.service = service
        self._rows_signature = ""

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        source_label(body, 0)
        section = Section(body, "Captured connections")
        section.grid(row=2, column=0, sticky="nsew")
        section.grid_rowconfigure(1, weight=1)
        self.table_host = ctk.CTkFrame(section, fg_color="transparent")
        self.table_host.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.table_host.grid_columnconfigure(0, weight=1)
        self.refresh_live()

    def refresh_live(self) -> None:
        rows = self.service.get_connections()
        rows_sig = signature(rows)
        if rows_sig != self._rows_signature:
            render_table(
                self.table_host,
                ["Time", "Process", "Pid", "Source IP", "Destination IP", "Port", "Protocol", "Direction", "Risk", "Basis"],
                rows,
                [2, 2, 1, 2, 2, 1, 1, 1, 1, 3],
                "No connections captured yet.",
            )
            self._rows_signature = rows_sig
        self.after(REFRESH_MS, self.refresh_live)
