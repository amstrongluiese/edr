from __future__ import annotations

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.pages.live_helpers import REFRESH_MS, render_metrics, render_table, signature, source_label


class IncidentsPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Incidents", "Real stored incidents and correlated detection findings")
        self.service = service
        self._summary_signature = ""
        self._rows_signature = ""

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(3, weight=1)

        source_label(body, 0)
        self.summary = ctk.CTkFrame(body, fg_color="transparent")
        self.summary.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        incidents = Section(body, "Incident queue")
        incidents.grid(row=3, column=0, sticky="nsew")
        incidents.grid_rowconfigure(1, weight=1)
        self.table_host = ctk.CTkFrame(incidents, fg_color="transparent")
        self.table_host.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.table_host.grid_columnconfigure(0, weight=1)
        self.refresh_live()

    def refresh_live(self) -> None:
        rows = self.service.get_incidents()
        metrics = [
            {"label": "Open", "value": str(sum(1 for row in rows if row.get("status") == "open")), "delta": "live incident rows", "tone": "warning"},
            {"label": "High/Critical", "value": str(sum(1 for row in rows if row.get("severity") in {"high", "critical"})), "delta": "needs review", "tone": "danger"},
            {"label": "Correlated", "value": str(len(rows)), "delta": "from real findings", "tone": "info"},
        ]
        summary_sig = signature(metrics)
        if summary_sig != self._summary_signature:
            render_metrics(self.summary, metrics, columns=3)
            self._summary_signature = summary_sig
        rows_sig = signature(rows)
        if rows_sig != self._rows_signature:
            render_table(
                self.table_host,
                ["Incident ID", "Title", "Severity", "Risk Score", "Affected Device", "Related Alerts", "Timeline", "Evidence", "Mitre Mapping", "Status"],
                rows,
                [2, 3, 1, 1, 2, 3, 3, 4, 2, 1],
                "No incidents recorded yet.",
            )
            self._rows_signature = rows_sig
        self.after(REFRESH_MS, self.refresh_live)
