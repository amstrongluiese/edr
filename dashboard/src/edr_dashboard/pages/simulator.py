from __future__ import annotations

import threading

import customtkinter as ctk

from edr_dashboard.components import DataTable, Page, Section
from edr_dashboard.pages.live_helpers import render_table, source_label
from edr_dashboard.theme import COLORS, FONT_SMALL


class ValidationSimulatorPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Validation Simulator", "Safe cybersecurity detection tests using synthetic telemetry")
        self.service = service
        self.rows: list[dict] = []

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(3, weight=1)

        source_label(body, 0)

        controls = ctk.CTkFrame(body, fg_color="transparent")
        controls.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        for index, (label, key) in enumerate(
            [
                ("Unknown Device Test", "unknown_device"),
                ("Safe Device TN Test", "safe_device"),
                ("DNS Test", "dns"),
                ("Beaconing Test", "beaconing"),
                ("Repeated Connection Test", "repeated_connection"),
                ("Traffic Spike Test", "traffic_spike"),
            ]
        ):
            ctk.CTkButton(
                controls,
                text=label,
                height=34,
                corner_radius=8,
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_hover"],
                command=lambda value=key: self.run_test(value),
            ).grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 8, 0))
            controls.grid_columnconfigure(index, weight=1)

        ctk.CTkButton(
            controls,
            text="Generate AI Validation Summary",
            height=34,
            corner_radius=8,
            fg_color=COLORS["info"],
            hover_color=COLORS["accent_hover"],
            command=self.generate_validation_summary,
        ).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        self.status_label = ctk.CTkLabel(
            body,
            text="Run a validation test to generate expected vs actual detection results.",
            font=FONT_SMALL,
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.status_label.grid(row=2, column=0, sticky="ew", pady=(0, 10))

        results = Section(body, "Validation results")
        results.grid(row=3, column=0, sticky="nsew")
        results.grid_rowconfigure(1, weight=1)
        self.table_host = ctk.CTkFrame(results, fg_color="transparent")
        self.table_host.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.table_host.grid_columnconfigure(0, weight=1)
        self.render()

    def run_test(self, test_key: str) -> None:
        self.status_label.configure(text=f"Running {test_key.replace('_', ' ')}...")

        def worker() -> None:
            try:
                row = self.service.run_validation_test(test_key)
            except Exception as exc:
                row = {
                    "test": test_key,
                    "expected_result": "Validation simulator should complete without errors.",
                    "actual_result": str(exc),
                    "pass_fail": "FAIL",
                    "evidence": "Exception raised while running test.",
                }
            self.after(0, lambda: self.finish_test(row))

        threading.Thread(target=worker, daemon=True).start()

    def finish_test(self, row: dict) -> None:
        self.rows.insert(0, row)
        self.status_label.configure(text=f"{row['test']} complete: {row['pass_fail']}")
        self.render()

    def generate_validation_summary(self) -> None:
        self.status_label.configure(text="Generating AI validation summary...")

        def worker() -> None:
            try:
                result = self.service.generate_ai_security_summary({"mode": "Offline", "max_items": 150}, scope="validation")
                outputs = ", ".join(result.get("outputs", {}).values())
                message = f"AI validation summary saved: {outputs}"
            except Exception as exc:
                message = f"AI validation summary failed: {exc}"
            self.after(0, lambda: self.status_label.configure(text=message))

        threading.Thread(target=worker, daemon=True).start()

    def render(self) -> None:
        render_table(
            self.table_host,
            ["Test", "Expected Result", "Actual Result", "Pass Fail", "Evidence"],
            self.rows,
            [2, 4, 3, 1, 5],
            "No validation tests have been run yet.",
        )
