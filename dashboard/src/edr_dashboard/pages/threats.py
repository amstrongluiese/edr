from __future__ import annotations

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.pages.live_helpers import REFRESH_MS, render_metrics, render_table, signature, source_label


class ThreatsPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Alerts", "Live detection-engine alerts, MITRE context, and triage status")
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

        threats = Section(body, "Threat findings")
        threats.grid(row=3, column=0, sticky="nsew")
        threats.grid_rowconfigure(1, weight=1)
        self.table_host = ctk.CTkFrame(threats, fg_color="transparent")
        self.table_host.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.table_host.grid_columnconfigure(0, weight=1)
        self.refresh_live()

    def refresh_live(self) -> None:
        rows = self.service.get_alerts()
        counts = {
            "critical": sum(1 for row in rows if str(row.get("severity", "")).lower() == "critical"),
            "high": sum(1 for row in rows if str(row.get("severity", "")).lower() == "high"),
            "medium": sum(1 for row in rows if str(row.get("severity", "")).lower() == "medium"),
            "mapped": sum(1 for row in rows if row.get("mitre")),
        }
        metrics = [
            {"label": "Critical", "value": str(counts["critical"]), "delta": "live findings", "tone": "danger" if counts["critical"] else "success"},
            {"label": "High", "value": str(counts["high"]), "delta": "live findings", "tone": "danger"},
            {"label": "Medium", "value": str(counts["medium"]), "delta": "triage queue", "tone": "warning"},
            {"label": "Mapped", "value": str(counts["mapped"]), "delta": "MITRE mapped", "tone": "info"},
        ]
        summary_sig = signature(metrics)
        if summary_sig != self._summary_signature:
            render_metrics(self.summary, metrics)
            self._summary_signature = summary_sig
        rows_sig = signature(rows)
        if rows_sig != self._rows_signature:
            render_table(
                self.table_host,
                ["Alert ID", "Time", "Severity", "Alert Type", "Device Host", "IP Address", "Risk Score", "Mitre", "Basis Evidence", "Status"],
                rows,
                [2, 2, 1, 2, 2, 2, 1, 3, 3, 1],
                "No alerts generated yet.",
            )
            self._rows_signature = rows_sig
        self.after(REFRESH_MS, self.refresh_live)
