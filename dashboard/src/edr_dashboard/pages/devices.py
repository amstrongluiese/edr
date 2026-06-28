from __future__ import annotations

import threading

import customtkinter as ctk

from edr_dashboard.device_discovery import ScanResult
from edr_dashboard.components import DataTable, MetricCard, Page, Section
from edr_dashboard.pages.live_helpers import REFRESH_MS, signature
from edr_dashboard.theme import COLORS, FONT_BODY, FONT_SMALL


class DevicesPage(Page):
    def __init__(self, master, service) -> None:
        super().__init__(master, "Devices", "Local Windows LAN/WiFi discovery, trust status, and risk review")
        self.service = service
        self.active_filter = "All"
        self.rows: list[dict] = []
        self.table_frame: ctk.CTkFrame | None = None
        self.empty_label: ctk.CTkLabel | None = None
        self.status_label: ctk.CTkLabel | None = None
        self.scan_status_label: ctk.CTkLabel | None = None
        self.fast_scan_button: ctk.CTkButton | None = None
        self.filter_buttons: dict[str, ctk.CTkButton] = {}
        self._rows_signature = ""

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        summary = ctk.CTkFrame(body, fg_color="transparent")
        summary.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        summary.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.discovered_card = MetricCard(summary, "Discovered", "0", "from ARP, ping, neighbor table", "info")
        self.discovered_card.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self.trusted_card = MetricCard(summary, "Trusted", "0", "matched in trusted inventory", "success")
        self.trusted_card.grid(row=0, column=1, sticky="ew", padx=(0, 12))
        self.suspicious_card = MetricCard(summary, "Suspicious", "0", "unknown local devices", "warning")
        self.suspicious_card.grid(row=0, column=2, sticky="ew", padx=(0, 12))
        self.scan_card = MetricCard(summary, "Scan Status", "Idle", "Fast Scan every 2.5 seconds", "info")
        self.scan_card.grid(row=0, column=3, sticky="ew")

        controls = ctk.CTkFrame(body, fg_color="transparent")
        controls.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        controls.grid_columnconfigure(4, weight=1)

        for column, label in enumerate(["All", "Trusted", "Unknown", "Suspicious"]):
            button = ctk.CTkButton(
                controls,
                text=label,
                width=104,
                height=34,
                corner_radius=8,
                fg_color=COLORS["accent"] if label == self.active_filter else COLORS["surface"],
                hover_color=COLORS["accent_hover"],
                text_color="#ffffff" if label == self.active_filter else COLORS["text"],
                border_color=COLORS["border"],
                border_width=1,
                command=lambda value=label: self.set_filter(value),
            )
            button.grid(row=0, column=column, sticky="w", padx=(0, 8))
            self.filter_buttons[label] = button

        self.fast_scan_button = ctk.CTkButton(
            controls,
            text="Fast Scan: On",
            width=128,
            height=34,
            corner_radius=8,
            fg_color=COLORS["success"],
            hover_color=COLORS["accent_hover"],
            command=self.toggle_fast_scan,
        )
        self.fast_scan_button.grid(row=0, column=5, sticky="e", padx=(8, 0))

        ctk.CTkButton(
            controls,
            text="Scan Network",
            width=128,
            height=34,
            corner_radius=8,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self.scan_network,
        ).grid(row=0, column=6, sticky="e", padx=(8, 0))
        ctk.CTkButton(
            controls,
            text="Refresh",
            width=104,
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_alt"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            border_width=1,
            command=self.refresh,
        ).grid(row=0, column=7, sticky="e", padx=(8, 0))

        devices = Section(body, "Device inventory")
        devices.grid(row=2, column=0, sticky="nsew")
        devices.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(
            devices,
            text="Data Source: Live SQLite / Sensor Telemetry",
            font=FONT_SMALL,
            text_color=COLORS["muted"],
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))

        ctk.CTkLabel(
            devices,
            text=(
                "Only same-network devices can be detected. Phones may appear only after they generate traffic "
                "(open a website, ping the gateway, or reconnect WiFi)."
            ),
            font=FONT_SMALL,
            text_color=COLORS["muted"],
            anchor="w",
        ).grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 10))

        self.table_host = ctk.CTkFrame(devices, fg_color="transparent")
        self.table_host.grid(row=3, column=0, sticky="nsew", padx=18, pady=(0, 10))
        self.table_host.grid_columnconfigure(0, weight=1)
        self.table_host.grid_rowconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            devices,
            text="",
            font=FONT_SMALL,
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.status_label.grid(row=4, column=0, sticky="ew", padx=18, pady=(0, 14))
        self.scan_status_label = ctk.CTkLabel(
            devices,
            text="Scanning: No | Last Scan Time: Never | Devices Found: 0",
            font=FONT_SMALL,
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.scan_status_label.grid(row=5, column=0, sticky="ew", padx=18, pady=(0, 14))

        self.service.register_device_scan_callback(self.on_scan_result)
        self.service.start_fast_device_scan()
        self.refresh()
        self.after(REFRESH_MS, self.refresh_live)
        self.after(500, self.refresh_scan_status)

    def set_filter(self, value: str) -> None:
        self.active_filter = value
        for label, button in self.filter_buttons.items():
            button.configure(
                fg_color=COLORS["accent"] if label == value else COLORS["surface"],
                text_color="#ffffff" if label == value else COLORS["text"],
            )
        self.render_table()

    def refresh(self) -> None:
        self.rows = self.service.list_discovered_devices()
        self._rows_signature = signature(self.rows)
        self.status_label.configure(text="Loaded saved local network inventory. Fast Scan is watching for new devices.")
        self.render_table()

    def refresh_live(self) -> None:
        rows = self.service.list_discovered_devices()
        rows_sig = signature(rows)
        if rows_sig != self._rows_signature:
            self.rows = rows
            self._rows_signature = rows_sig
            self.render_table()
        self.after(REFRESH_MS, self.refresh_live)

    def scan_network(self) -> None:
        self.status_label.configure(text="Scanning local network with ping sweep, ARP table, and Windows neighbor table...")

        def worker() -> None:
            result = self.service.scan_network_fast()
            self.after(0, lambda: self.finish_scan(result.rows, result))

        threading.Thread(target=worker, daemon=True).start()

    def finish_scan(self, rows: list[dict], result: ScanResult | None = None) -> None:
        self.rows = rows
        self._rows_signature = signature(rows)
        if result and result.is_scanning:
            self.status_label.configure(text="Scan already running. Showing latest saved inventory.")
        elif result:
            self.status_label.configure(
                text=f"Scan complete. {result.discovered_count} active device(s) observed; {len(rows)} total saved to SQLite."
            )
        else:
            self.status_label.configure(text=f"Scan complete. {len(rows)} device(s) saved to SQLite.")
        self.render_table()
        self.refresh_scan_status(schedule_next=False)

    def on_scan_result(self, result: ScanResult) -> None:
        self.after(0, lambda: self.finish_scan(result.rows, result))

    def toggle_fast_scan(self) -> None:
        status = self.service.get_device_scan_status()
        if status.fast_scan_enabled:
            self.service.stop_fast_device_scan()
            self.status_label.configure(text="Fast Scan paused. Use Scan Network for a manual test.")
        else:
            self.service.start_fast_device_scan()
            self.status_label.configure(text="Fast Scan enabled. Scanning every 2.5 seconds for active local devices.")
        self.refresh_scan_status(schedule_next=False)

    def refresh_scan_status(self, schedule_next: bool = True) -> None:
        status = self.service.get_device_scan_status()
        scanning_text = "Yes" if status.is_scanning else "No"
        fast_text = "On" if status.fast_scan_enabled else "Off"
        self.scan_status_label.configure(
            text=(
                f"Scanning: {scanning_text} | Last Scan Time: {status.last_scan_time} | "
                f"Devices Found: {status.devices_found} | New Last Scan: {status.new_devices_found}"
            )
        )
        self._set_metric(self.scan_card, "Scanning" if status.is_scanning else "Idle")
        if self.fast_scan_button is not None:
            self.fast_scan_button.configure(
                text=f"Fast Scan: {fast_text}",
                fg_color=COLORS["success"] if status.fast_scan_enabled else COLORS["surface"],
                text_color="#ffffff" if status.fast_scan_enabled else COLORS["text"],
            )
        if schedule_next:
            self.after(500, self.refresh_scan_status)

    def filtered_rows(self) -> list[dict]:
        if self.active_filter == "Trusted":
            return [row for row in self.rows if row.get("trust_status") == "Trusted"]
        if self.active_filter == "Unknown":
            return [row for row in self.rows if row.get("trust_status") == "Unknown Device"]
        if self.active_filter == "Suspicious":
            return [row for row in self.rows if row.get("risk_level") == "Suspicious"]
        return self.rows

    def render_table(self) -> None:
        for child in self.table_host.winfo_children():
            child.destroy()

        trusted = sum(1 for row in self.rows if row.get("trust_status") == "Trusted")
        suspicious = sum(1 for row in self.rows if row.get("risk_level") == "Suspicious")
        self._set_metric(self.discovered_card, str(len(self.rows)))
        self._set_metric(self.trusted_card, str(trusted))
        self._set_metric(self.suspicious_card, str(suspicious))

        rows = self.filtered_rows()
        if not rows:
            empty = ctk.CTkFrame(self.table_host, fg_color=COLORS["surface_alt"], border_color=COLORS["border"], border_width=1, corner_radius=6)
            empty.grid(row=0, column=0, sticky="nsew")
            empty.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                empty,
                text=(
                    "No devices discovered yet. Connect a device to the same WiFi/router and generate traffic, "
                    "or use Fast Scan / Scan Network."
                ),
                font=FONT_BODY,
                text_color=COLORS["muted"],
                height=80,
            ).grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
            return

        DataTable(
            self.table_host,
            ["IP Address", "MAC Address", "Hostname", "Vendor", "Device Type", "Trust Status", "Risk Level", "Discovery Source"],
            rows,
            [2, 2, 2, 2, 2, 2, 1, 2],
        ).grid(row=0, column=0, sticky="nsew")

    def _set_metric(self, card: MetricCard, value: str) -> None:
        labels = [child for child in card.winfo_children() if isinstance(child, ctk.CTkLabel)]
        if labels:
            labels[0].configure(text=value)
