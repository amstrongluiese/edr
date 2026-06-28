from __future__ import annotations

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.pages.live_helpers import REFRESH_MS, render_table, signature, source_label
from edr_dashboard.theme import COLORS


class DnsAnalyticsPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "DNS Analytics", "DNS telemetry and detection coverage")
        self.service = service
        self._rows_signature = ""

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(3, weight=1)

        source_label(body, 0)
        ctk.CTkButton(
            body,
            text="Future DNS Collector Integration",
            width=220,
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_alt"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            border_width=1,
            state="disabled",
        ).grid(row=1, column=0, sticky="w", pady=(0, 12))

        section = Section(body, "DNS logs")
        section.grid(row=3, column=0, sticky="nsew")
        section.grid_rowconfigure(1, weight=1)
        self.table_host = ctk.CTkFrame(section, fg_color="transparent")
        self.table_host.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.table_host.grid_columnconfigure(0, weight=1)
        self.refresh_live()

    def refresh_live(self) -> None:
        rows = self.service.get_dns_logs()
        rows_sig = signature(rows)
        if rows_sig != self._rows_signature:
            render_table(
                self.table_host,
                ["Time", "Device", "Query", "Event Type", "Risk", "Basis"],
                rows,
                [2, 2, 4, 2, 1, 2],
                "No DNS telemetry available yet.",
            )
            self._rows_signature = rows_sig
        self.after(REFRESH_MS, self.refresh_live)
