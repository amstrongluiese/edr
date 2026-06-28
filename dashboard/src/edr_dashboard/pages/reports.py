from __future__ import annotations

import threading

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.pages.live_helpers import REFRESH_MS, render_metrics, render_table, signature, source_label
from edr_dashboard.theme import COLORS, FONT_SMALL


class ReportsPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Reports", "Live investigation summaries, exports, and executive reporting")
        self.service = service
        self._summary_signature = ""
        self._rows_signature = ""

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(4, weight=1)

        source_label(body, 0)
        self.summary = ctk.CTkFrame(body, fg_color="transparent")
        self.summary.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        actions = ctk.CTkFrame(body, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        actions.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(
            actions,
            text="Generate AI Security Report",
            height=34,
            corner_radius=6,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self.generate_ai_report,
        ).grid(row=0, column=0, sticky="w")
        self.ai_status = ctk.CTkLabel(actions, text="", font=FONT_SMALL, text_color=COLORS["muted"], anchor="w")
        self.ai_status.grid(row=0, column=1, sticky="ew", padx=(12, 0))

        reports = Section(body, "Report library")
        reports.grid(row=4, column=0, sticky="nsew")
        reports.grid_rowconfigure(1, weight=1)
        self.table_host = ctk.CTkFrame(reports, fg_color="transparent")
        self.table_host.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.table_host.grid_columnconfigure(0, weight=1)
        self.refresh_live()

    def generate_ai_report(self) -> None:
        self.ai_status.configure(text="Generating AI security report...")

        def worker() -> None:
            try:
                result = self.service.generate_ai_security_summary({"mode": "Offline", "max_items": 150}, scope="all")
                outputs = ", ".join(result.get("outputs", {}).values())
                message = f"AI report saved: {outputs}"
            except Exception as exc:
                message = f"AI report failed: {exc}"
            self.after(0, lambda: self.ai_status.configure(text=message))

        threading.Thread(target=worker, daemon=True).start()

    def refresh_live(self) -> None:
        rows = self.service.list_reports()
        metrics = [
            {"label": "Drafts", "value": str(sum(1 for row in rows if row.get("status") == "draft")), "delta": "stored reports", "tone": "warning"},
            {"label": "Generated", "value": str(len(rows)), "delta": "report artifacts", "tone": "info"},
            {"label": "Exported", "value": str(sum(1 for row in rows if row.get("status") == "exported")), "delta": "available locally", "tone": "success"},
        ]
        summary_sig = signature(metrics)
        if summary_sig != self._summary_signature:
            render_metrics(self.summary, metrics, columns=3)
            self._summary_signature = summary_sig
        rows_sig = signature(rows)
        if rows_sig != self._rows_signature:
            render_table(self.table_host, ["Title", "Type", "Status", "Updated"], rows, [3, 1, 1, 1], "No reports generated yet.")
            self._rows_signature = rows_sig
        self.after(REFRESH_MS, self.refresh_live)
