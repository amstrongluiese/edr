from __future__ import annotations

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
from edr_core.full_scan import run_full_scan
from edr_core.log_monitor import import_log_file
from edr_core.reports import generate_all_reports
from edr_core.threat_intel import seed_intel_db, threat_intel_counts
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
        WHERE is_inventory_device = 1
        ORDER BY online_status DESC, risk_score DESC, last_seen DESC
        LIMIT 500
        """,
        ["ip", "hostname", "mac", "vendor", "device_type", "online_status", "trust_status", "risk_level", "risk_score", "discovery_source", "first_seen", "last_seen"],
    ),
    "Files": ("SELECT timestamp, path, extension, sha256, signed_status, source, risk_score FROM file_events ORDER BY id DESC LIMIT 500", ["timestamp", "path", "extension", "sha256", "signed_status", "source", "risk_score"]),
    "Processes": ("SELECT timestamp, process_name, pid, parent_process, command_line, executable_path, sha256, source FROM process_events ORDER BY id DESC LIMIT 500", ["timestamp", "process_name", "pid", "parent_process", "command_line", "executable_path", "sha256", "source"]),
    "Alerts": (
        """
        SELECT MAX(last_seen) AS last_seen,
               alert_type,
               entity,
               (SELECT severity FROM alerts a2 WHERE a2.alert_type = alerts.alert_type AND a2.entity = alerts.entity ORDER BY score DESC LIMIT 1) AS severity,
               MAX(score) AS score,
               SUM(occurrence_count) AS occurrence_count,
               (SELECT reason FROM alerts a3 WHERE a3.alert_type = alerts.alert_type AND a3.entity = alerts.entity ORDER BY last_seen DESC LIMIT 1) AS reason,
               (SELECT mitre_id FROM alerts a4 WHERE a4.alert_type = alerts.alert_type AND a4.entity = alerts.entity ORDER BY last_seen DESC LIMIT 1) AS mitre_id,
               'grouped' AS status
        FROM alerts
        GROUP BY alert_type, entity
        ORDER BY MAX(score) DESC, SUM(occurrence_count) DESC, MAX(last_seen) DESC
        LIMIT 500
        """,
        ["last_seen", "alert_type", "entity", "severity", "score", "occurrence_count", "reason", "mitre_id", "status"],
    ),
    "Connections": ("SELECT timestamp, process_name, pid, source_ip, destination_ip, port, protocol, event_type FROM connections ORDER BY id DESC LIMIT 500", ["timestamp", "process_name", "pid", "source_ip", "destination_ip", "port", "protocol", "event_type"]),
    "DNS": ("SELECT timestamp, source_ip, domain, query_type, resolved_ip FROM dns_logs ORDER BY id DESC LIMIT 500", ["timestamp", "source_ip", "domain", "query_type", "resolved_ip"]),
    "Logs": ("SELECT timestamp, log_source, event_type, username, source_ip, device, target_system, outcome FROM log_events ORDER BY id DESC LIMIT 500", ["timestamp", "log_source", "event_type", "username", "source_ip", "device", "target_system", "outcome"]),
    "Failed Attempts": ("SELECT timestamp, username, source_ip, device, target_system, failed_count, window_seconds, status FROM failed_attempts ORDER BY id DESC LIMIT 500", ["timestamp", "username", "source_ip", "device", "target_system", "failed_count", "window_seconds", "status"]),
    "Threat Intelligence": ("SELECT indicator, indicator_type, source, confidence, last_seen FROM threat_intelligence ORDER BY indicator_type, indicator LIMIT 500", ["indicator", "indicator_type", "source", "confidence", "last_seen"]),
    "CVE Matches": ("SELECT timestamp, product, version, cve_id, cvss, severity, description FROM cve_matches ORDER BY id DESC LIMIT 500", ["timestamp", "product", "version", "cve_id", "cvss", "severity", "description"]),
    "MITRE Mapping": ("SELECT last_seen, alert_type, entity, mitre_tactic, mitre_technique, mitre_id, reason FROM alerts ORDER BY last_seen DESC LIMIT 500", ["last_seen", "alert_type", "entity", "mitre_tactic", "mitre_technique", "mitre_id", "reason"]),
    "Performance": ("SELECT timestamp, metric_name, metric_value, unit, context FROM performance_metrics ORDER BY id DESC LIMIT 500", ["timestamp", "metric_name", "metric_value", "unit", "context"]),
    "Incidents": ("SELECT updated_at, title, severity, score, status, evidence FROM incidents ORDER BY id DESC LIMIT 500", ["updated_at", "title", "severity", "score", "status", "evidence"]),
    "Reports": ("SELECT created_at, report_type, path, summary FROM reports ORDER BY id DESC LIMIT 500", ["created_at", "report_type", "path", "summary"]),
    "Validation": ("SELECT timestamp, test_name, expected_malicious, detected_malicious, outcome, response_ms, notes FROM validation_results ORDER BY id DESC LIMIT 500", ["timestamp", "test_name", "expected_malicious", "detected_malicious", "outcome", "response_ms", "notes"]),
}


class EdrDashboard(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        init_db()
        seed_intel_db()
        self.title("Enterprise EDR SOC Console")
        self.geometry("1440x860")
        self.minsize(1180, 720)
        self.configure(bg=BG)
        self.current_page = "Overview"
        self.sort_state: dict[str, bool] = {}
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
            "Performance", "Incidents", "Validation", "Reports", "AI Analyst", "Settings",
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
        self._pill_button(header, "Refresh", lambda: self.show_page(page)).pack(side="right")

        if page == "Overview":
            self.page_overview()
        elif page == "Full Scan":
            self.page_full_scan()
        elif page == "Logs":
            self.page_logs()
        elif page == "Validation":
            self.page_validation()
        elif page == "Reports":
            self.page_reports()
        elif page == "AI Analyst":
            self.page_ai()
        elif page == "Settings":
            self.page_settings()
        else:
            sql, columns = PAGE_QUERIES[page]
            self.page_table(sql, columns)

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
        counts = summarize_counts()
        metrics = tk.Frame(self.main, bg=BG)
        metrics.pack(fill="x", padx=24, pady=(0, 14))
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

        self._mini_table(left, "Recent Alerts", "SELECT last_seen, severity, alert_type, entity, score, occurrence_count FROM alerts ORDER BY score DESC, occurrence_count DESC, last_seen DESC LIMIT 12", ["last_seen", "severity", "alert_type", "entity", "score", "occurrence_count"])
        self._mini_table(left, "Connected Devices", "SELECT ip, hostname, device_type, risk_level, online_status FROM devices WHERE is_inventory_device = 1 ORDER BY online_status DESC, risk_score DESC, last_seen DESC LIMIT 12", ["ip", "hostname", "device_type", "risk_level", "online_status"])
        self._mini_table(right, "Recent Incidents", "SELECT updated_at, severity, title, score FROM incidents ORDER BY id DESC LIMIT 10", ["updated_at", "severity", "title", "score"])
        self._ai_summary_panel(right)

    def _mini_table(self, parent: tk.Widget, title: str, sql: str, columns: list[str]) -> None:
        frame = self._panel(parent)
        frame.pack(fill="both", expand=True, pady=(0, 12))
        tk.Label(frame, text=title, bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(0, 8))
        rows = [[str(row[col]) if row[col] is not None else "" for col in columns] for row in fetch_all(sql)]
        self._tree(frame, columns, rows, compact=True)

    def _ai_summary_panel(self, parent: tk.Widget) -> None:
        frame = self._panel(parent)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="AI Summary", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(0, 8))
        summary = "\n".join(generate_analysis().splitlines()[:12])
        tk.Label(frame, text=summary or "No recorded evidence yet.", bg=PANEL, fg=TEXT, justify="left", wraplength=360, font=("Segoe UI", 9)).pack(anchor="nw", fill="both", expand=True)

    def page_full_scan(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Run Full Endpoint Scan", self.full_scan_action, True).pack(side="left", padx=(0, 8))
        self._pill_button(actions, "Snapshot Monitored Files", self.file_snapshot_action).pack(side="left")
        self.page_table("SELECT timestamp, scan_type, target, item_type, risk_score, risk_level, status FROM scan_results ORDER BY id DESC LIMIT 500", ["timestamp", "scan_type", "target", "item_type", "risk_score", "risk_level", "status"])

    def page_logs(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Import Log File", self.import_log_action, True).pack(side="left")
        self.page_table(*PAGE_QUERIES.get("Logs", ("SELECT timestamp, log_source, event_type, username, source_ip, device, target_system, outcome FROM log_events ORDER BY id DESC LIMIT 500", ["timestamp", "log_source", "event_type", "username", "source_ip", "device", "target_system", "outcome"])))

    def page_validation(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Run Validation Simulator", self.run_validation_action, True).pack(side="left")
        self.page_table(*PAGE_QUERIES["Validation"])

    def page_reports(self) -> None:
        actions = tk.Frame(self.main, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 12))
        self._pill_button(actions, "Generate Reports", self.generate_reports_action, True).pack(side="left")
        self.page_table(*PAGE_QUERIES["Reports"])

    def page_table(self, sql: str, columns: list[str]) -> None:
        container = self._panel(self.main, 12, 12)
        container.pack(fill="both", expand=True, padx=24, pady=(0, 18))
        toolbar = tk.Frame(container, bg=PANEL)
        toolbar.pack(fill="x", pady=(0, 10))
        tk.Label(toolbar, text="Search", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        search_var = tk.StringVar()
        search = tk.Entry(toolbar, textvariable=search_var, bd=0, bg="#eef6fc", fg=TEXT, insertbackground=TEXT, font=("Segoe UI", 10))
        search.pack(side="left", fill="x", expand=True, padx=(8, 0), ipady=7)

        rows = [[str(row[col]) if row[col] is not None else "" for col in columns] for row in fetch_all(sql)]
        tree = self._tree(container, columns, rows)

        def apply_filter(*_: Any) -> None:
            query = search_var.get().lower().strip()
            filtered = rows if not query else [row for row in rows if query in " ".join(row).lower()]
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
        summary = run_validation()
        messagebox.showinfo("Validation Complete", f"Accuracy: {summary['accuracy']:.2%}\nFPR: {summary['false_positive_rate']:.2%}\nFNR: {summary['false_negative_rate']:.2%}\nTotals: {summary['totals']}")
        self.show_page("Validation")

    def generate_reports_action(self) -> None:
        paths = generate_all_reports()
        messagebox.showinfo("Reports Generated", "\n".join(str(path) for path in paths))
        self.show_page("Reports")

    def full_scan_action(self) -> None:
        result = run_full_scan()
        messagebox.showinfo("Full Scan Complete", "\n".join(f"{key}: {value}" for key, value in result.items()))
        self.show_page("Full Scan")

    def file_snapshot_action(self) -> None:
        count = snapshot_monitored_files()
        messagebox.showinfo("File Monitor", f"Recorded {count} monitored file observations.")
        self.show_page("Files")

    def import_log_action(self) -> None:
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
        count = import_discovered_devices()
        repair_all()
        messagebox.showinfo("Device Discovery", f"Imported {count} visible local-network devices.")
        self.show_page("Devices")

    def repair_action(self) -> None:
        result = repair_all()
        messagebox.showinfo("Data Quality Repair", str(result))
        self.show_page("Overview")


def main() -> None:
    app = EdrDashboard()
    app.mainloop()


if __name__ == "__main__":
    main()
