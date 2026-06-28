from __future__ import annotations

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.pages.live_helpers import REFRESH_MS, debug_panel, render_metrics, render_table, signature, source_label


class DashboardPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Dashboard", "Live endpoint posture and active response overview")
        self.service = service
        self._metric_signature = ""
        self._alert_signature = ""
        self._timeline_signature = ""

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure((0, 1, 2, 3), weight=1)
        body.grid_rowconfigure(2, weight=1, minsize=320)

        source_label(body, 0)

        self.metrics_host = ctk.CTkFrame(body, fg_color="transparent")
        self.metrics_host.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(0, 6))

        alerts = Section(body, "Priority alerts")
        alerts.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=(0, 10))
        alerts.grid_rowconfigure(1, weight=1)
        self.alerts_host = ctk.CTkFrame(alerts, fg_color="transparent")
        self.alerts_host.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.alerts_host.grid_columnconfigure(0, weight=1)
        self.alerts_host.grid_rowconfigure(0, weight=1)

        timeline = Section(body, "Activity timeline")
        timeline.grid(row=2, column=3, sticky="nsew")
        timeline.grid_rowconfigure(1, weight=1)
        self.timeline_host = ctk.CTkFrame(timeline, fg_color="transparent")
        self.timeline_host.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.timeline_host.grid_columnconfigure(0, weight=1)
        self.timeline_host.grid_rowconfigure(0, weight=1)

        debug_panel(body, service, 3)
        self.refresh_live()

    def refresh_live(self) -> None:
        metrics = self.service.get_dashboard_metrics()
        metric_sig = signature(metrics)
        if metric_sig != self._metric_signature:
            render_metrics(self.metrics_host, metrics, columns=4)
            self._metric_signature = metric_sig

        alerts = self.service.get_alerts()[:8]
        alert_sig = signature(alerts)
        if alert_sig != self._alert_signature:
            render_table(
                self.alerts_host,
                ["Time", "Severity", "Alert Type", "Device Host", "Risk Score", "Mitre", "Status"],
                alerts,
                [2, 1, 2, 2, 1, 3, 1],
                "No alerts generated yet.",
            )
            self._alert_signature = alert_sig

        timeline = self.service.threat_timeline()
        timeline_sig = signature(timeline)
        if timeline_sig != self._timeline_signature:
            render_table(self.timeline_host, ["Time", "Event", "Device", "Details"], timeline, [1, 2, 1, 2], "No telemetry activity yet.")
            self._timeline_signature = timeline_sig

        self.after(REFRESH_MS, self.refresh_live)
