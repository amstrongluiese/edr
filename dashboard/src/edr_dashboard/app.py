from __future__ import annotations

from datetime import datetime

import customtkinter as ctk

from edr_dashboard.live_data import LiveDashboardService
from edr_dashboard.pages.ai_analyst import AIAnalystPage
from edr_dashboard.pages.connections import ConnectionsPage
from edr_dashboard.pages.dashboard import DashboardPage
from edr_dashboard.pages.devices import DevicesPage
from edr_dashboard.pages.dns import DnsAnalyticsPage
from edr_dashboard.pages.incidents import IncidentsPage
from edr_dashboard.pages.reports import ReportsPage
from edr_dashboard.pages.settings import SettingsPage
from edr_dashboard.pages.simulator import ValidationSimulatorPage
from edr_dashboard.pages.threats import ThreatsPage
from edr_dashboard.pages.traffic import TrafficAnalyticsPage
from edr_dashboard.theme import COLORS, FONT_BODY, FONT_HEADING, FONT_TITLE


DashboardService = LiveDashboardService


class Sidebar(ctk.CTkFrame):
    def __init__(self, master: ctk.CTk, on_select) -> None:
        super().__init__(master, width=236, fg_color=COLORS["sidebar"], corner_radius=0)
        self.grid_propagate(False)
        self._on_select = on_select
        self._buttons: dict[str, ctk.CTkButton] = {}

        brand = ctk.CTkFrame(self, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 18))
        brand.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            brand,
            text="EDR Console",
            font=FONT_TITLE,
            text_color=COLORS["sidebar_text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(
            brand,
            text="Enterprise SOC Console",
            font=FONT_BODY,
            text_color=COLORS["sidebar_muted"],
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(4, 0))

        nav = [
            ("Dashboard", "\u25a6", "Dashboard"),
            ("Devices", "\u25a3", "Devices"),
            ("Threats", "\u26a0", "Alerts"),
            ("Connections", "\u21c4", "Connections"),
            ("DNS", "\u25ce", "DNS Analytics"),
            ("Traffic", "\u223f", "Traffic Analytics"),
            ("Incidents", "\u25c8", "Incidents"),
            ("Simulator", "\u2697", "Validation Simulator"),
            ("AIAnalyst", "\u25c7", "AI Analyst"),
            ("Reports", "\u25a4", "Reports"),
            ("Settings", "\u2699", "Settings"),
        ]

        for index, (key, icon, label) in enumerate(nav, start=1):
            button = ctk.CTkButton(
                self,
                text=f"{icon}   {label}",
                anchor="w",
                height=38,
                corner_radius=6,
                fg_color="transparent",
                hover_color=COLORS["sidebar_hover"],
                text_color=COLORS["sidebar_text"],
                font=FONT_BODY,
                command=lambda page=key: self._on_select(page),
            )
            button.grid(row=index, column=0, sticky="ew", padx=12, pady=2)
            self._buttons[key] = button

        self.grid_rowconfigure(20, weight=1)
        status = ctk.CTkFrame(self, fg_color=COLORS["sidebar_panel"], corner_radius=8)
        status.grid(row=21, column=0, sticky="ew", padx=12, pady=14)
        status.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            status,
            text="Sensor Mesh",
            font=FONT_BODY,
            text_color=COLORS["sidebar_text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 0))
        ctk.CTkLabel(
            status,
            text="Live SQLite telemetry",
            font=FONT_BODY,
            text_color=COLORS["sidebar_muted"],
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", padx=12, pady=(2, 10))

    def set_active(self, page: str) -> None:
        for key, button in self._buttons.items():
            if key == page:
                button.configure(fg_color=COLORS["accent"], text_color="#ffffff")
            else:
                button.configure(fg_color="transparent", text_color=COLORS["sidebar_text"])


class TopBar(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame) -> None:
        super().__init__(master, fg_color=COLORS["surface"], corner_radius=0, height=64)
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self,
            text="Security Operations",
            font=FONT_HEADING,
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(10, 0))
        ctk.CTkLabel(
            self,
            text="Local EDR console backed by SQLite, sensor telemetry, and LAN discovery",
            font=FONT_BODY,
            text_color=COLORS["muted"],
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=22)

        self.refresh_label = ctk.CTkLabel(
            self,
            text="Last refresh: --",
            font=FONT_BODY,
            text_color=COLORS["muted"],
            anchor="e",
        )
        self.refresh_label.grid(row=0, column=1, rowspan=2, sticky="e", padx=(0, 14))

        ctk.CTkLabel(
            self,
            text="\u25cf Live",
            font=FONT_BODY,
            text_color=COLORS["success"],
            anchor="e",
        ).grid(row=0, column=2, rowspan=2, sticky="e", padx=(0, 14))

        ctk.CTkButton(
            self,
            text="Refresh",
            width=96,
            height=32,
            corner_radius=6,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self._update_refresh_time,
        ).grid(row=0, column=3, rowspan=2, padx=(0, 22), pady=16)
        self._update_refresh_time()

    def _update_refresh_time(self) -> None:
        self.refresh_label.configure(text=f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")


class DashboardApp:
    def __init__(self, service: LiveDashboardService | None = None) -> None:
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self.service = service or DashboardService()
        self.root = ctk.CTk()
        self.root.title("EDR Console")
        self.root.geometry("1360x820")
        self.root.minsize(1180, 720)
        self.root.configure(fg_color=COLORS["background"])

        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        self.sidebar = Sidebar(self.root, self.show_page)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        shell = ctk.CTkFrame(self.root, fg_color=COLORS["background"], corner_radius=0)
        shell.grid(row=0, column=1, sticky="nsew")
        shell.grid_columnconfigure(0, weight=1)
        shell.grid_rowconfigure(1, weight=1)

        self.topbar = TopBar(shell)
        self.topbar.grid(row=0, column=0, sticky="ew")

        self.content = ctk.CTkFrame(shell, fg_color=COLORS["background"], corner_radius=0)
        self.content.grid(row=1, column=0, sticky="nsew", padx=16, pady=14)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.pages = {
            "Dashboard": DashboardPage(self.content, self.service),
            "Devices": DevicesPage(self.content, self.service),
            "Threats": ThreatsPage(self.content, self.service),
            "Connections": ConnectionsPage(self.content, self.service),
            "DNS": DnsAnalyticsPage(self.content, self.service),
            "Traffic": TrafficAnalyticsPage(self.content, self.service),
            "Incidents": IncidentsPage(self.content, self.service),
            "Simulator": ValidationSimulatorPage(self.content, self.service),
            "AIAnalyst": AIAnalystPage(self.content, self.service),
            "Reports": ReportsPage(self.content, self.service),
            "Settings": SettingsPage(self.content, self.service),
        }

        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

        self.show_page("Dashboard")

    def show_page(self, page_name: str) -> None:
        self.pages[page_name].tkraise()
        self.sidebar.set_active(page_name)

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    DashboardApp().run()


if __name__ == "__main__":
    main()
