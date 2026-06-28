from __future__ import annotations

import threading

import customtkinter as ctk

from edr_dashboard.components import Page, Section
from edr_dashboard.pages.live_helpers import source_label
from edr_dashboard.theme import COLORS, FONT_BODY, FONT_SMALL


class AIAnalystPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "AI Analyst", "SOC-style report intelligence over alerts, incidents, validation, MITRE, and telemetry")
        self.service = service
        self.last_result: dict | None = None

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(3, weight=1)

        source_label(body, 0)

        controls = Section(body, "AI settings")
        controls.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        controls.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.mode = ctk.CTkOptionMenu(controls, values=["Offline", "Ollama", "OpenAI-Compatible"])
        self.mode.set("Offline")
        self.mode.grid(row=1, column=0, sticky="ew", padx=(12, 8), pady=(0, 12))

        self.model_name = ctk.CTkEntry(controls, placeholder_text="Model Name")
        self.model_name.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(0, 12))

        self.api_base_url = ctk.CTkEntry(controls, placeholder_text="API Base URL")
        self.api_base_url.grid(row=1, column=2, sticky="ew", padx=(0, 8), pady=(0, 12))

        self.api_key = ctk.CTkEntry(controls, placeholder_text="API Key optional", show="*")
        self.api_key.grid(row=1, column=3, sticky="ew", padx=(0, 8), pady=(0, 12))

        self.max_items = ctk.CTkEntry(controls, placeholder_text="Max items")
        self.max_items.insert(0, "150")
        self.max_items.grid(row=1, column=4, sticky="ew", padx=(0, 12), pady=(0, 12))

        actions = ctk.CTkFrame(body, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        actions.grid_columnconfigure((0, 1, 2, 3), weight=1)
        for index, (label, scope) in enumerate(
            [
                ("Generate AI Summary", "all"),
                ("Analyze Latest Reports", "reports"),
                ("Analyze All Incidents", "incidents"),
                ("Export AI Report", "export"),
            ]
        ):
            ctk.CTkButton(
                actions,
                text=label,
                height=34,
                corner_radius=6,
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_hover"],
                command=lambda value=scope: self.run_action(value),
            ).grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 8, 0))

        preview = Section(body, "AI report preview")
        preview.grid(row=3, column=0, sticky="nsew")
        preview.grid_rowconfigure(1, weight=1)
        preview.grid_columnconfigure(0, weight=1)
        self.preview = ctk.CTkTextbox(preview, font=FONT_BODY, wrap="word")
        self.preview.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 8))
        self.preview.insert("1.0", "No AI analysis generated yet.")

        self.status_label = ctk.CTkLabel(
            preview,
            text="Status: Ready",
            font=FONT_SMALL,
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.status_label.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 10))

    def run_action(self, scope: str) -> None:
        if scope == "export":
            if self.last_result:
                outputs = ", ".join(self.last_result.get("outputs", {}).values())
                self.status_label.configure(text=f"Status: Exported to {outputs}")
            else:
                self.status_label.configure(text="Status: Generate a report before exporting.")
            return
        self.status_label.configure(text="Status: Generating AI analysis...")

        def worker() -> None:
            try:
                result = self.service.generate_ai_security_summary(self.settings(), scope=scope)
            except Exception as exc:
                result = {"text": f"AI analysis failed: {exc}", "outputs": {}, "mode_used": "error"}
            self.after(0, lambda: self.finish(result))

        threading.Thread(target=worker, daemon=True).start()

    def finish(self, result: dict) -> None:
        self.last_result = result
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", result.get("text", "No AI analysis generated."))
        outputs = result.get("outputs", {})
        self.status_label.configure(
            text=f"Status: Generated via {result.get('mode_used', 'unknown')}. Saved {len(outputs)} file(s)."
        )

    def settings(self) -> dict:
        try:
            max_items = int(self.max_items.get() or "150")
        except ValueError:
            max_items = 150
        return {
            "mode": self.mode.get(),
            "model_name": self.model_name.get(),
            "api_base_url": self.api_base_url.get(),
            "api_key": self.api_key.get(),
            "max_items": max(1, min(max_items, 500)),
        }
