from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from edr_core.ai_analyst import generate_analysis
from edr_core.data_quality import repair_all
from edr_core.db import fetch_all, init_db
from edr_core.device_discovery import import_discovered_devices
from edr_core.detection import summarize_counts
from edr_core.file_monitor import snapshot_monitored_files
from edr_core.dns_monitor import collect_dns_cache, detect_doh_connections
from edr_core.full_scan import collect_windows_event_logs, run_full_scan, scan_open_ports, scan_processes, scan_services, scan_startup_programs
from edr_core.live_presence import scan_presence
from edr_core.log_monitor import import_log_file
from edr_core.reports import generate_all_reports
from edr_core.sessions import get_current_session_id, set_current_session_id, start_session, stop_session
from edr_core.threat_intel import seed_intel_db, threat_intel_counts
from edr_core.testing_verification import run_testing_verification
from edr_core.validation import run_validation


BG = "#eef3f8"
SIDEBAR = "#f8fbff"
PANEL = "#fbfdff"
PANEL_ALT = "#f4f8fd"
CARD = "#ffffff"
TEXT = "#162033"
MUTED = "#667085"
ACCENT = "#0ea5e9"
ACCENT_DARK = "#0369a1"
DANGER = "#dc2626"
WARN = "#b45309"
SUCCESS = "#059669"
BORDER = "#d9e3ef"


PAGE_QUERIES: dict[str, tuple[str, list[str]]] = {
    "Devices": (
        """
        SELECT ip, hostname, mac, vendor, device_type, online_status, trust_status, risk_level,
               risk_score, discovery_source, first_seen, last_seen
        FROM devices
        WHERE is_inventory_device = 1 AND session_id = ?
        ORDER BY online_status DESC, risk_score DESC, last_seen DESC
        LIMIT 500
        """,
        ["ip", "hostname", "mac", "vendor", "device_type", "online_status", "trust_status", "risk_level", "risk_score", "discovery_source", "first_seen", "last_seen"],
    ),
    "Files": ("SELECT timestamp, path, extension, sha256, signed_status, source, risk_score FROM file_events WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "path", "extension", "sha256", "signed_status", "source", "risk_score"]),
    "Processes": ("SELECT timestamp, process_name, pid, parent_process, command_line, executable_path, sha256, source FROM process_events WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "process_name", "pid", "parent_process", "command_line", "executable_path", "sha256", "source"]),
    "Alerts": (
        """
        SELECT MAX(last_seen) AS last_seen,
               alert_type,
               entity,
               (SELECT severity FROM alerts a2 WHERE a2.alert_type = alerts.alert_type AND a2.entity = alerts.entity AND a2.session_id = alerts.session_id ORDER BY score DESC LIMIT 1) AS severity,
               MAX(score) AS score,
               SUM(occurrence_count) AS occurrence_count,
               (SELECT reason FROM alerts a3 WHERE a3.alert_type = alerts.alert_type AND a3.entity = alerts.entity AND a3.session_id = alerts.session_id ORDER BY last_seen DESC LIMIT 1) AS reason,
               (SELECT mitre_id FROM alerts a4 WHERE a4.alert_type = alerts.alert_type AND a4.entity = alerts.entity AND a4.session_id = alerts.session_id ORDER BY last_seen DESC LIMIT 1) AS mitre_id,
               'grouped' AS status
        FROM alerts
        WHERE session_id = ?
        GROUP BY alert_type, entity
        ORDER BY MAX(score) DESC, SUM(occurrence_count) DESC, MAX(last_seen) DESC
        LIMIT 500
        """,
        ["last_seen", "alert_type", "entity", "severity", "score", "occurrence_count", "reason", "mitre_id", "status"],
    ),
    "Connections": ("SELECT timestamp, process_name, pid, source_ip, destination_ip, source_port, port, direction, protocol, event_type FROM connections WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "process_name", "pid", "source_ip", "destination_ip", "source_port", "port", "direction", "protocol", "event_type"]),
    "DNS": ("SELECT timestamp, source_ip, domain, query_type, resolved_ip FROM dns_logs WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "source_ip", "domain", "query_type", "resolved_ip"]),
    "Logs": ("SELECT timestamp, log_source, event_type, username, source_ip, device, target_system, outcome FROM log_events WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "log_source", "event_type", "username", "source_ip", "device", "target_system", "outcome"]),
    "Failed Attempts": ("SELECT timestamp, username, source_ip, device, target_system, failed_count, window_seconds, status FROM failed_attempts WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "username", "source_ip", "device", "target_system", "failed_count", "window_seconds", "status"]),
    "Threat Intelligence": ("SELECT indicator, indicator_type, source, confidence, last_seen FROM threat_intelligence WHERE ? IS NOT NULL ORDER BY indicator_type, indicator LIMIT 500", ["indicator", "indicator_type", "source", "confidence", "last_seen"]),
    "CVE Matches": ("SELECT timestamp, product, version, cve_id, cvss, severity, description FROM cve_matches WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "product", "version", "cve_id", "cvss", "severity", "description"]),
    "MITRE Mapping": ("SELECT last_seen, alert_type, entity, mitre_tactic, mitre_technique, mitre_id, reason FROM alerts WHERE session_id = ? ORDER BY last_seen DESC LIMIT 500", ["last_seen", "alert_type", "entity", "mitre_tactic", "mitre_technique", "mitre_id", "reason"]),
    "Performance": ("SELECT timestamp, metric_name, metric_value, unit, context FROM performance_metrics WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "metric_name", "metric_value", "unit", "context"]),
    "Incidents": ("SELECT updated_at, title, severity, score, status, evidence FROM incidents WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["updated_at", "title", "severity", "score", "status", "evidence"]),
    "Reports": ("SELECT created_at, report_type, path, summary FROM reports WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["created_at", "report_type", "path", "summary"]),
    "Validation": ("SELECT timestamp, test_name, expected_malicious, detected_malicious, outcome, response_ms, notes FROM validation_results WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "test_name", "expected_malicious", "detected_malicious", "outcome", "response_ms", "notes"]),
    "Archive / History": ("SELECT session_id, started_at, stopped_at, status, total_alerts, total_incidents, detection_accuracy, archive_path FROM sessions ORDER BY started_at DESC LIMIT 500", ["session_id", "started_at", "stopped_at", "status", "total_alerts", "total_incidents", "detection_accuracy", "archive_path"]),
}


class EdrDashboard(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        init_db()
        seed_intel_db()
        set_current_session_id(None)
        self.title("Enterprise EDR SOC Console")
        self.geometry("1440x860")
        self.minsize(1180, 720)
        self.configure(bg=BG)
        self.current_page = "Overview"
        self.monitor_status = "Monitoring Not Started"
        self.scan_status = "Stopped"
        self.last_refresh = "Never"
        self.monitoring_running = False
        self.stop_event = threading.Event()
        self.sort_state: dict[str, bool] = {}
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._configure_style()
        self._build_shell()
        self.show_page("Overview")

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", rowheight=31, font=("Segoe UI", 9), fieldbackground=CARD, background=CARD, borderwidth=0)
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9), background="#eaf2fb", foreground=TEXT, relief="flat", padding=(8, 8))
        style.map("Treeview", background=[("selected", "#dff3ff")], foreground=[("selected", TEXT)])
        style.configure("Vertical.TScrollbar", gripcount=0, background="#dbeafe", troughcolor="#f8fbff", bordercolor="#f8fbff", arrowcolor=ACCENT_DARK)
        style.configure("Horizontal.TScrollbar", gripcount=0, background="#dbeafe", troughcolor="#f8fbff", bordercolor="#f8fbff", arrowcolor=ACCENT_DARK)

    def _build_shell(self) -> None:
        self.sidebar = tk.Frame(self, bg=SIDEBAR, width=236, highlightthickness=1, highlightbackground=BORDER)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=SIDEBAR)
        brand.pack(fill="x", padx=18, pady=(20, 14))
        tk.Label(brand, text="Enterprise EDR", bg=SIDEBAR, fg=TEXT, font=("Segoe UI Semibold", 17)).pack(anchor="w")
        tk.Label(brand, text="SOC command center", bg=SIDEBAR, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

        pages = [
            "Overview", "Full Scan", "Devices", "Files", "Processes", "Alerts", "Connections", "DNS",
            "Logs", "Failed Attempts", "Threat Intelligence", "CVE Matches", "MITRE Mapping",
            "Performance", "Incidents", "Validation", "Testing Verification", "Reports", "Archive / History", "AI Analyst", "Settings",
        ]
        self.nav_buttons: dict[str, tk.Button] = {}
        for page in pages:
            button = tk.Button(
                self.sidebar,
                text=page,
                anchor="w",
                bd=0,
                relief="flat",
                padx=14,
                pady=9,
                bg=SIDEBAR,
                fg=TEXT,
                activebackground="#e6f4ff",
                activeforeground=ACCENT_DARK,
                font=("Segoe UI", 10),
                command=lambda p=page: self.show_page(p),
            )
            button.pack(fill="x", padx=12, pady=1)
            self.nav_buttons[page] = button

        self.main = tk.Frame(self, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)

    def _clear(self) -> None:
        for child in self.main.winfo_children():
            child.destroy()

    def show_page(self, page: str) -> None:
        self.current_page = page
        self._clear()
        for name, button in self.nav_buttons.items():
            active = name == page
            button.configure(bg="#e6f4ff" if active else SIDEBAR, fg=ACCENT_DARK if active else TEXT)

        header = tk.Frame(self.main, bg=BG)
        header.pack(fill="x", padx=24, pady=(18, 12))
        tk.Label(header, text=page, bg=BG, fg=TEXT, font=("Segoe UI Semibold", 24)).pack(side="left")
        tk.Label(header, text=f"{self.monitor_status} | {self.scan_status} | Last refresh: {self.last_refresh}", bg=BG, fg=SUCCESS if self.monitoring_running else MUTED, font=("Segoe UI Semibold", 10)).pack(side="left", padx=(18, 0))
        self._pill_button(header, "Refresh", lambda: self.show_page(page)).pack(side="right")
        if self.monitoring_running:
            self._pill_button(header, "Stop Monitoring", self.stop_monitoring_action).pack(side="right", padx=(0, 8))
        else:
            self._pill_button(header, "Start Monitoring", self.start_monitoring_action, True).pack(side="right", padx=(0, 8))

        if page == "Overview":
            self.page_overview()
        elif page == "Full Scan":
            self.page_full_scan()
        elif page == "Logs":
            self.page_logs()
        elif page == "Validation":
            self.page_validation()
        elif page == "Testing Verification":
            self.page_testing_verification()
        elif page == "Reports":
            self.page_reports()
        elif page == "AI Analyst":
            self.page_ai()
        elif page == "Settings":
            self.page_settings()
        else:
            sql, columns = PAGE_QUERIES[page]
            self.page_table(sql, columns, archive=(page == "Archive / History"))

    def _panel(self, parent: tk.Widget, padx: int = 16, pady: int = 14) -> tk.Frame:
        frame = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        frame.configure(padx=padx, pady=pady)
        return frame

    def _pill_button(self, parent: tk.Widget, text: str, command: Any, accent: bool = False) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bd=0,
            padx=16,
            pady=8,
            bg=ACCENT if accent else "#e8f3fb",
            fg="#ffffff" if accent else ACCENT_DARK,
            activebackground="#0284c7" if accent else "#d8edf9",
            activeforeground="#ffffff" if accent else ACCENT_DARK,
            font=("Segoe UI Semibold", 9),
            cursor="hand2",
        )

    def metric_card(self, parent: tk.Widget, title: str, value: str, subtext: str = "", color: str = TEXT) -> None:
        frame = self._panel(parent, 14, 12)
        frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tk.Label(frame, text=title.upper(), bg=PANEL, fg=MUTED, font=("Segoe UI Semibold", 8)).pack(anchor="w")
        tk.Label(frame, text=value, bg=PANEL, fg=color, font=("Segoe UI Semibold", 22)).pack(anchor="w", pady=(3, 0))
        if subtext:
            tk.Label(frame, text=subtext, bg=PANEL, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))

    def page_overview(self) -> None:
        session_id = get_current_session_id()
        counts = summarize_counts(session_id)
        metrics = tk.Frame(self.main, bg=BG)
        metrics.pack(fill="x", padx=24, pady=(0, 14))
        self.metric_card(metrics, "Session", session_id or "Not Started", f"{self.monitor_status} / {self.scan_status}", SUCCESS if self.monitoring_running else TEXT)
        self.metric_card(metrics, "Unique Devices", str(counts["unique_devices"]), f"{counts['online_devices']} online / {counts['offline_devices']} offline")
        self.metric_card(metrics, "Active Connections", str(counts["connections"]), "endpoint telemetry")
        self.metric_card(metrics, "Grouped Alerts", str(counts["grouped_alerts"]), "deduplicated", DANGER if counts["grouped_alerts"] else TEXT)
        self.metric_card(metrics, "Incidents", str(counts["incidents"]), "correlated evidence", WARN if counts["incidents"] else TEXT)
        self.metric_card(metrics, "Risk Score", str(counts["risk_score"]), "max inventory risk", self._risk_color(counts["risk_score"]))

        body = tk.Frame(self.main, bg=BG)
        body.pack(fill="both", expand=True, padx=24, pady=(0, 18))
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        right = tk.Frame(body, bg=BG, width=430)
        right.pack(side="left", fill="both")

        self._mini_table(left, "Recent Alerts", "SELECT last_seen, severity, alert_type, entity, score, occurrence_count FROM alerts WHERE session_id = ? ORDER BY score DESC, occurrence_count DESC, last_seen DESC LIMIT 12", ["last_seen", "severity", "alert_type", "entity", "score", "occurrence_count"], session_id)
        self._mini_table(left, "Connected Devices", "SELECT ip, hostname, device_type, risk_level, online_status FROM devices WHERE is_inventory_device = 1 AND session_id = ? ORDER BY online_status DESC, risk_score DESC, last_seen DESC LIMIT 12", ["ip", "hostname", "device_type", "risk_level", "online_status"], session_id)
        self._mini_table(right, "Recent Incidents", "SELECT updated_at, severity, title, score FROM incidents WHERE session_id = ? ORDER BY id DESC LIMIT 10", ["updated_at", "severity", "title", "score"], session_id)
        self._ai_summary_panel(right)

        note = self._panel(self.main, 12, 10)
        note.pack(fill="x", padx=24, pady=(0, 12))
        tk.Label(
            note,
            text="DNS visibility is limited to this endpoint unless router DNS logs or external agents are configured. Some browsers use DNS-over-HTTPS, which may prevent normal DNS query visibility.",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9),
            wraplength=980,
            justify="left",
        ).pack(anchor="w")

    def _mini_table(self, parent: tk.Widget, title: str, sql: str, columns: list[str], session_id: str | None) -> None:
        frame = self._panel(parent)
        frame.pack(fill="both", expand=True, pady=(0, 12))
        tk.Label(frame, text=title, bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(0, 8))
        rows = [] if not session_id else [[str(row[col]) if row[col] is not None else "" for col in columns] for row in fetch_all(sql, (session_id,))]
        self._tree(frame, columns, rows, compact=True)

    def _ai_summary_panel(self, parent: tk.Widget) -> None:
        frame = self._panel(parent)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="AI Summary", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(0, 8))
        summary = "\n".join(generate_analysis(session_id=get_current_session_id()).splitlines()[:12])
        tk.Label(frame, text=summary or "No recorded evidence yet.", bg=PANEL, fg=TEXT, justify="left", wraplength=360, font=("Segoe UI", 9)).pack(anchor="nw", fill="both", expand=True)

    def page_full_scan(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Run Full Endpoint Scan", self.full_scan_action, True).pack(side="left", padx=(0, 8))
        self._pill_button(actions, "Snapshot Monitored Files", self.file_snapshot_action).pack(side="left")
        self.page_table("SELECT timestamp, scan_type, target, item_type, risk_score, risk_level, status FROM scan_results WHERE session_id = ? ORDER BY id DESC LIMIT 500", ["timestamp", "scan_type", "target", "item_type", "risk_score", "risk_level", "status"])

    def page_logs(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Import Log File", self.import_log_action, True).pack(side="left")
        self.page_table(*PAGE_QUERIES["Logs"])

    def page_validation(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Run Validation Simulator", self.run_validation_action, True).pack(side="left")
        self.page_table(*PAGE_QUERIES["Validation"])

    def page_testing_verification(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Run Testing Verification", self.testing_verification_action, True).pack(side="left")
        self.page_table(
            "SELECT timestamp, test_name, expected_result, actual_result, pass_fail, outcome, detection_time_ms, evidence FROM testing_verification WHERE session_id = ? ORDER BY id DESC LIMIT 500",
            ["timestamp", "test_name", "expected_result", "actual_result", "pass_fail", "outcome", "detection_time_ms", "evidence"],
        )

    def page_reports(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Generate Reports", self.generate_reports_action, True).pack(side="left")
        self.page_table(*PAGE_QUERIES["Reports"])

    def page_table(self, sql: str, columns: list[str], archive: bool = False) -> None:
        container = self._panel(self.main, 12, 12)
        container.pack(fill="both", expand=True, padx=24, pady=(0, 18))
        toolbar = tk.Frame(container, bg=PANEL)
        toolbar.pack(fill="x", pady=(0, 10))
        tk.Label(toolbar, text="Search", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        search_var = tk.StringVar()
        search = tk.Entry(toolbar, textvariable=search_var, bd=0, bg="#eef6fc", fg=TEXT, insertbackground=TEXT, font=("Segoe UI", 10))
        search.pack(side="left", fill="x", expand=True, padx=(8, 0), ipady=7)
        status_var = tk.StringVar(value="All")
        if self.current_page == "Devices":
            for label in ["All", "Online", "Offline", "Unknown", "Trusted"]:
                self._pill_button(toolbar, label, lambda value=label: (status_var.set(value), apply_filter())).pack(side="left", padx=(8, 0))

        session_id = get_current_session_id()
        if archive:
            rows = [[str(row[col]) if row[col] is not None else "" for col in columns] for row in fetch_all(sql)]
        elif not session_id:
            rows = []
        else:
            rows = [[str(row[col]) if row[col] is not None else "" for col in columns] for row in fetch_all(sql, (session_id,))]
        tree = self._tree(container, columns, rows)

        def apply_filter(*_: Any) -> None:
            query = search_var.get().lower().strip()
            filtered = rows if not query else [row for row in rows if query in " ".join(row).lower()]
            if self.current_page == "Devices":
                status = status_var.get().lower()
                if status != "all":
                    if status == "unknown":
                        filtered = [row for row in filtered if "unknown" in " ".join(row).lower()]
                    elif status == "trusted":
                        filtered = [row for row in filtered if "trusted" in " ".join(row).lower()]
                    else:
                        filtered = [row for row in filtered if status in " ".join(row).lower()]
            self._replace_tree_rows(tree, filtered)

        search_var.trace_add("write", apply_filter)

    def _tree(self, parent: tk.Widget, columns: list[str], rows: list[list[str]], compact: bool = False) -> ttk.Treeview:
        holder = tk.Frame(parent, bg=PANEL)
        holder.pack(fill="both", expand=True)
        tree = ttk.Treeview(holder, columns=columns, show="headings", height=8 if compact else 18)
        tree.tag_configure("odd", background=CARD)
        tree.tag_configure("even", background=PANEL_ALT)
        tree.tag_configure("critical", foreground=DANGER)
        tree.tag_configure("high", foreground=WARN)
        tree.tag_configure("ok", foreground=SUCCESS)
        vsb = ttk.Scrollbar(holder, orient="vertical", command=tree.yview, style="Vertical.TScrollbar")
        hsb = ttk.Scrollbar(holder, orient="horizontal", command=tree.xview, style="Horizontal.TScrollbar")
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        for col in columns:
            tree.heading(col, text=col.replace("_", " ").title(), command=lambda c=col, t=tree: self._sort_tree(t, c))
            width = 110 if compact else max(120, min(300, len(col) * 18))
            tree.column(col, width=width, anchor="w", stretch=True)
        self._replace_tree_rows(tree, rows)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        holder.rowconfigure(0, weight=1)
        holder.columnconfigure(0, weight=1)
        return tree

    def _replace_tree_rows(self, tree: ttk.Treeview, rows: list[list[str]]) -> None:
        tree.delete(*tree.get_children())
        for index, row in enumerate(rows):
            text = " ".join(row).lower()
            tags = ["even" if index % 2 else "odd"]
            if "critical" in text or "high risk" in text:
                tags.append("critical")
            elif "suspicious" in text or "low risk" in text:
                tags.append("high")
            elif "online" in text or "informational" in text:
                tags.append("ok")
            tree.insert("", "end", values=row, tags=tuple(tags))

    def _sort_tree(self, tree: ttk.Treeview, col: str) -> None:
        descending = self.sort_state.get(col, False)
        data = [(tree.set(item, col), item) for item in tree.get_children("")]
        try:
            data.sort(key=lambda item: float(item[0]), reverse=descending)
        except ValueError:
            data.sort(key=lambda item: item[0].lower(), reverse=descending)
        for index, (_, item) in enumerate(data):
            tree.move(item, "", index)
        self.sort_state[col] = not descending

    def _risk_color(self, score: int) -> str:
        if score > 80:
            return DANGER
        if score > 60:
            return WARN
        if score > 30:
            return "#d97706"
        return SUCCESS if score else TEXT

    def page_ai(self) -> None:
        frame = self._panel(self.main, 18, 16)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 18))
        text = tk.Text(frame, wrap="word", bg=PANEL, fg=TEXT, font=("Consolas", 10), relief="flat", bd=0)
        text.pack(fill="both", expand=True)
        text.insert("1.0", generate_analysis())
        text.configure(state="disabled")

    def page_settings(self) -> None:
        frame = self._panel(self.main, 18, 16)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 18))
        counts = threat_intel_counts()
        tk.Label(frame, text="System Controls", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 14)).pack(anchor="w")
        tk.Label(frame, text=f"Threat-intelligence cache: {counts}", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 14))
        self._pill_button(frame, "Run Network-Wide Device Discovery", self.discovery_action, True).pack(anchor="w", pady=4)
        self._pill_button(frame, "Refresh Local Threat Intel Cache", self.refresh_intel_action).pack(anchor="w", pady=4)
        self._pill_button(frame, "Repair Device/Alert Data Quality", self.repair_action).pack(anchor="w", pady=4)
        tk.Label(
            frame,
            text="Unknown devices stay informational. Inventory counts include visible LAN devices, not validation/test or remote passive IPs.",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9),
            wraplength=760,
            justify="left",
        ).pack(anchor="w", pady=(16, 0))

    def run_validation_action(self) -> None:
        if not get_current_session_id():
            messagebox.showinfo("Monitoring Not Started", "Start Monitoring before running validation.")
            return
        summary = run_validation()
        messagebox.showinfo("Validation Complete", f"Accuracy: {summary['accuracy']:.2%}\nFPR: {summary['false_positive_rate']:.2%}\nFNR: {summary['false_negative_rate']:.2%}\nTotals: {summary['totals']}")
        self.show_page("Validation")

    def testing_verification_action(self) -> None:
        if not get_current_session_id():
            messagebox.showinfo("Monitoring Not Started", "Start Monitoring before running testing verification.")
            return
        summary = run_testing_verification()
        messagebox.showinfo("Testing Verification", f"Accuracy: {summary['accuracy']:.2%}\nTotals: {summary['totals']}")
        self.show_page("Testing Verification")

    def generate_reports_action(self) -> None:
        if not get_current_session_id():
            messagebox.showinfo("Monitoring Not Started", "Start Monitoring before generating live reports.")
            return
        paths = generate_all_reports()
        messagebox.showinfo("Reports Generated", "\n".join(str(path) for path in paths))
        self.show_page("Reports")

    def full_scan_action(self) -> None:
        if not get_current_session_id():
            messagebox.showinfo("Monitoring Not Started", "Start Monitoring before running a full scan.")
            return
        result = run_full_scan()
        messagebox.showinfo("Full Scan Complete", "\n".join(f"{key}: {value}" for key, value in result.items()))
        self.show_page("Full Scan")

    def file_snapshot_action(self) -> None:
        if not get_current_session_id():
            messagebox.showinfo("Monitoring Not Started", "Start Monitoring before collecting file observations.")
            return
        count = snapshot_monitored_files()
        messagebox.showinfo("File Monitor", f"Recorded {count} monitored file observations.")
        self.show_page("Files")

    def import_log_action(self) -> None:
        if not get_current_session_id():
            messagebox.showinfo("Monitoring Not Started", "Start Monitoring before importing logs.")
            return
        path = filedialog.askopenfilename(title="Import authentication/server/database/application log")
        if path:
            count = import_log_file(Path(path))
            messagebox.showinfo("Logs Imported", f"Imported {count} log events.")
            self.show_page("Logs")

    def refresh_intel_action(self) -> None:
        seed_intel_db()
        messagebox.showinfo("Threat Intel", "Local threat-intelligence cache refreshed.")
        self.show_page("Settings")

    def discovery_action(self) -> None:
        if not get_current_session_id():
            messagebox.showinfo("Monitoring Not Started", "Start Monitoring before device discovery.")
            return
        count = import_discovered_devices()
        repair_all()
        messagebox.showinfo("Device Discovery", f"Imported {count} visible local-network devices.")
        self.show_page("Devices")

    def repair_action(self) -> None:
        result = repair_all()
        messagebox.showinfo("Data Quality Repair", str(result))
        self.show_page("Overview")

    def start_monitoring_action(self) -> None:
        if self.monitoring_running:
            return
        session_id = start_session()
        self.monitoring_running = True
        self.monitor_status = "Monitoring Active"
        self.scan_status = "Scanning"
        self.stop_event.clear()
        self.show_page("Overview")
        threading.Thread(target=self._initial_collection_worker, args=(session_id,), daemon=True).start()
        threading.Thread(target=self._live_monitor_loop, args=(session_id,), daemon=True).start()

    def _initial_collection_worker(self, session_id: str) -> None:
        set_current_session_id(session_id)
        try:
            import_discovered_devices()
            scan_processes()
            scan_services()
            scan_startup_programs()
            scan_open_ports()
            collect_windows_event_logs(25)
            collect_dns_cache()
            detect_doh_connections()
            repair_all()
        finally:
            self.scan_status = "Idle" if self.monitoring_running else "Stopped"
            self.after(0, lambda: self.show_page(self.current_page))

    def _live_monitor_loop(self, session_id: str) -> None:
        set_current_session_id(session_id)
        tick = 0
        while not self.stop_event.is_set() and get_current_session_id() == session_id:
            self.scan_status = "Scanning"
            try:
                scan_presence(offline_after_seconds=25)
                collect_dns_cache()
                detect_doh_connections()
                if tick % 3 == 0:
                    scan_open_ports()
                self.last_refresh = __import__("datetime").datetime.now().strftime("%H:%M:%S")
            except Exception as exc:
                self.scan_status = f"Idle (collector warning)"
            finally:
                self.scan_status = "Idle" if self.monitoring_running else "Stopped"
                self.after(0, lambda: self.show_page(self.current_page))
            tick += 1
            self.stop_event.wait(5)

    def stop_monitoring_action(self) -> None:
        session_id = get_current_session_id()
        self.stop_event.set()
        if not session_id:
            self.monitor_status = "Monitoring Stopped"
            self.monitoring_running = False
            self.show_page("Overview")
            return
        archive_dir = stop_session(session_id)
        self.monitoring_running = False
        self.monitor_status = "Monitoring Stopped"
        self.scan_status = "Stopped"
        messagebox.showinfo("Session Archived", f"Session {session_id} archived to:\n{archive_dir}")
        self.show_page("Overview")

    def on_close(self) -> None:
        if get_current_session_id():
            try:
                self.stop_event.set()
                stop_session(get_current_session_id() or "")
            except Exception:
                pass
        self.destroy()


def main() -> None:
    app = EdrDashboard()
    app.mainloop()


if __name__ == "__main__":
    main()
