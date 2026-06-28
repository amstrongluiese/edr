from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from edr_dashboard.device_discovery import DEFAULT_DB_PATH, DeviceInventoryService
from edr_dashboard.ai_security_analyst import AIAnalystSettings, AIReportIntelligence
from edr_dashboard.validation_simulator import CybersecurityValidationSimulator


DATA_SOURCE_LABEL = "Data Source: Live SQLite / Sensor Telemetry"


def _today_prefix() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _short_time(value: str | None) -> str:
    if not value:
        return ""
    return value.replace("T", " ").replace("Z", "")[:19]


def _payload(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _reasons(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return value
    if isinstance(parsed, list):
        return "; ".join(str(item) for item in parsed)
    return str(parsed)


def _mitre_text(value: str | None) -> str:
    return (value or "").replace(",", "; ")


class LiveDashboardService:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.device_inventory = DeviceInventoryService()
        self.validation_simulator = CybersecurityValidationSimulator(db_path)
        self.ai_report_intelligence = AIReportIntelligence(db_path)

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _table_exists(self, conn: sqlite3.Connection, table: str) -> bool:
        row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
        return row is not None

    def _count(self, conn: sqlite3.Connection, table: str, where: str = "", params: tuple = ()) -> int:
        if not self._table_exists(conn, table):
            return 0
        query = f"SELECT COUNT(*) AS count FROM {table}"
        if where:
            query += f" WHERE {where}"
        return int(conn.execute(query, params).fetchone()["count"])

    def _scalar(self, conn: sqlite3.Connection, query: str, params: tuple = (), default: Any = 0) -> Any:
        try:
            row = conn.execute(query, params).fetchone()
        except sqlite3.Error:
            return default
        if row is None:
            return default
        value = row[0]
        return default if value is None else value

    def list_discovered_devices(self) -> list[dict]:
        return self.device_inventory.list_devices()

    def scan_network(self) -> list[dict]:
        return self.device_inventory.scan_network(ping_sweep=True)

    def scan_network_fast(self):
        return self.device_inventory.scan_network_with_status(ping_sweep=True)

    def start_fast_device_scan(self) -> None:
        self.device_inventory.start_fast_scan()

    def stop_fast_device_scan(self) -> None:
        self.device_inventory.stop_fast_scan()

    def get_device_scan_status(self):
        return self.device_inventory.get_scan_status()

    def register_device_scan_callback(self, callback) -> None:
        self.device_inventory.register_scan_callback(callback)

    def get_devices(self) -> list[dict]:
        return self.list_discovered_devices()

    def list_assets(self) -> list[dict]:
        return self.list_discovered_devices()

    def get_dashboard_metrics(self) -> list[dict]:
        today = _today_prefix()
        with self._connect() as conn:
            lan_devices = self._count(conn, "lan_devices")
            assets = self._count(conn, "assets")
            total_devices = max(lan_devices, assets)
            unknown_devices = self._count(conn, "lan_devices", "trust_status != ?", ("Trusted",))
            active_connections = self._count(conn, "sensor_events", "event_type = ?", ("network.connection_observed",))
            threats_today = self._count(conn, "findings", "created_at_utc LIKE ?", (f"{today}%",))
            incidents_today = self._count(conn, "incidents", "opened_at_utc LIKE ?", (f"{today}%",))
            suspicious_dns = self._count(
                conn,
                "findings",
                "provider_id = ? OR metadata_json LIKE ? OR title LIKE ?",
                ("dns_analysis", "%dns_%", "%DNS%"),
            )
            avg_risk = round(float(self._scalar(conn, "SELECT AVG(score) FROM risk_assessments", default=0)))
            eval_metrics = self.get_cybersecurity_evaluation_metrics()
        online = total_devices
        posture_metrics = [
            {"label": "Total devices", "value": str(total_devices), "delta": "LAN inventory + sensor assets", "tone": "info"},
            {"label": "Devices online", "value": str(online), "delta": "seen in local telemetry", "tone": "success"},
            {"label": "Unknown devices", "value": str(unknown_devices), "delta": "not in trusted inventory", "tone": "warning"},
            {"label": "Active connections", "value": str(active_connections), "delta": "sensor network events", "tone": "info"},
            {"label": "Threats today", "value": str(threats_today), "delta": "detection findings", "tone": "danger" if threats_today else "success"},
            {"label": "Suspicious DNS", "value": str(suspicious_dns), "delta": "DNS findings/events", "tone": "warning"},
            {"label": "Incidents today", "value": str(incidents_today), "delta": "stored incidents", "tone": "warning"},
            {"label": "Overall risk", "value": str(avg_risk), "delta": "average risk score", "tone": "danger" if avg_risk >= 70 else "success"},
        ]
        return posture_metrics + eval_metrics

    def metrics(self) -> list[dict]:
        return self.get_dashboard_metrics()

    def get_cybersecurity_evaluation_metrics(self) -> list[dict]:
        with self._connect() as conn:
            if not self._table_exists(conn, "validation_metrics"):
                tp = tn = fp = fn = total = 0
                avg_response = avg_cpu = avg_memory = 0
            else:
                row = conn.execute(
                    """
                    SELECT
                        COALESCE(SUM(true_positive), 0),
                        COALESCE(SUM(true_negative), 0),
                        COALESCE(SUM(false_positive), 0),
                        COALESCE(SUM(false_negative), 0),
                        COUNT(*),
                        COALESCE(AVG(response_time_ms), 0),
                        COALESCE(AVG(cpu_usage_percent), 0),
                        COALESCE(AVG(memory_usage_mb), 0)
                    FROM validation_metrics
                    """
                ).fetchone()
                tp, tn, fp, fn, total, avg_response, avg_cpu, avg_memory = row
            ioc_matches = self._count(conn, "threat_intel_matches", "observable_kind != ?", ("cve",))
            cve_matches = self._count(conn, "threat_intel_matches", "observable_kind = ?", ("cve",))

        tested = int(tp or 0) + int(tn or 0) + int(fp or 0) + int(fn or 0)
        accuracy = round(((int(tp or 0) + int(tn or 0)) / tested) * 100, 1) if tested else 0
        fp_rate = round((int(fp or 0) / (int(fp or 0) + int(tn or 0))) * 100, 1) if (int(fp or 0) + int(tn or 0)) else 0
        fn_rate = round((int(fn or 0) / (int(fn or 0) + int(tp or 0))) * 100, 1) if (int(fn or 0) + int(tp or 0)) else 0

        return [
            {"label": "Detection accuracy", "value": f"{accuracy}%", "delta": f"TP {tp} / TN {tn} / tests {total}", "tone": "success" if accuracy >= 90 else "warning"},
            {"label": "False positive rate", "value": f"{fp_rate}%", "delta": f"FP {fp}", "tone": "success" if fp_rate <= 5 else "danger"},
            {"label": "False negative rate", "value": f"{fn_rate}%", "delta": f"FN {fn}", "tone": "success" if fn_rate <= 5 else "danger"},
            {"label": "Avg response time", "value": f"{round(float(avg_response or 0))} ms", "delta": "validation pipeline", "tone": "info"},
            {"label": "CPU usage", "value": f"{round(float(avg_cpu or 0), 1)}%", "delta": "during validation", "tone": "info"},
            {"label": "Memory usage", "value": f"{round(float(avg_memory or 0), 1)} MB", "delta": "during validation", "tone": "info"},
            {"label": "IoC matches", "value": str(ioc_matches), "delta": "threat-intel evidence", "tone": "danger" if ioc_matches else "success"},
            {"label": "CVE matches", "value": str(cve_matches), "delta": "vulnerability evidence", "tone": "warning" if cve_matches else "success"},
        ]

    def get_alerts(self) -> list[dict]:
        with self._connect() as conn:
            if self._table_exists(conn, "alerts") and self._count(conn, "alerts") > 0:
                rows = conn.execute(
                    """
                    SELECT
                        a.alert_id,
                        a.created_at_utc,
                        a.severity,
                        a.title,
                        a.provider_id,
                        a.description,
                        a.device_id,
                        a.risk_score,
                        a.status,
                        a.metadata_json,
                        se.payload_json,
                        GROUP_CONCAT(mm.tactic || ' / ' || mm.technique_id || ' ' || mm.technique_name, '; ') AS mitre
                    FROM alerts a
                    LEFT JOIN sensor_events se ON se.event_id = a.event_id
                    LEFT JOIN mitre_mappings mm ON mm.alert_id = a.alert_id
                    GROUP BY a.alert_id
                    ORDER BY a.created_at_utc DESC
                    LIMIT 150
                    """
                ).fetchall()
                alerts = []
                for row in rows:
                    payload = _payload(row["payload_json"])
                    metadata = _payload(row["metadata_json"])
                    alerts.append(
                        {
                            "alert_id": row["alert_id"],
                            "time": _short_time(row["created_at_utc"]),
                            "severity": row["severity"],
                            "alert_type": row["provider_id"],
                            "device_host": row["device_id"] or "Unknown",
                            "ip_address": payload.get("remote_address") or payload.get("local_address") or metadata.get("ip_address", ""),
                            "risk_score": row["risk_score"],
                            "mitre": row["mitre"] or "; ".join(metadata.get("mitre_mappings", [])),
                            "basis_evidence": row["description"] or row["title"],
                            "status": row["status"],
                        }
                    )
                return alerts

            if not self._table_exists(conn, "findings"):
                return []
            rows = conn.execute(
                """
                SELECT
                    f.finding_id,
                    f.created_at_utc,
                    f.severity,
                    f.title,
                    f.provider_id,
                    f.metadata_json,
                    se.asset_id,
                    se.payload_json,
                    COALESCE(ra.score, 0) AS risk_score,
                    GROUP_CONCAT(mt.tactic || ' / ' || mt.technique_id || ' ' || mt.name, '; ') AS mitre
                FROM findings f
                LEFT JOIN sensor_events se ON se.event_id = f.event_id
                LEFT JOIN risk_assessments ra ON ra.event_id = f.event_id
                LEFT JOIN finding_mitre_techniques fmt ON fmt.finding_id = f.finding_id
                LEFT JOIN mitre_techniques mt ON mt.technique_id = fmt.technique_id
                GROUP BY f.finding_id
                ORDER BY f.created_at_utc DESC
                LIMIT 150
                """
            ).fetchall()
        alerts = []
        for row in rows:
            payload = _payload(row["payload_json"])
            metadata = _payload(row["metadata_json"])
            alerts.append(
                {
                    "alert_id": row["finding_id"],
                    "time": _short_time(row["created_at_utc"]),
                    "severity": row["severity"],
                    "alert_type": row["provider_id"],
                    "device_host": row["asset_id"] or "Unknown",
                    "ip_address": payload.get("remote_address") or payload.get("local_address") or metadata.get("ip_address", ""),
                    "risk_score": row["risk_score"],
                    "mitre": row["mitre"] or "",
                    "basis_evidence": row["title"],
                    "status": "open",
                }
            )
        return alerts

    def list_alerts(self) -> list[dict]:
        return self.get_alerts()

    def get_incidents(self) -> list[dict]:
        with self._connect() as conn:
            if self._table_exists(conn, "incidents") and self._count(conn, "incidents") > 0:
                rows = conn.execute(
                    """
                    SELECT
                        i.incident_id,
                        i.title,
                        i.summary,
                        i.severity,
                        i.status,
                        i.owner,
                        i.opened_at_utc,
                        i.updated_at_utc,
                        i.metadata_json,
                        MAX(COALESCE(a.risk_score, 0)) AS risk_score,
                        GROUP_CONCAT(a.alert_id, ', ') AS related_alerts,
                        GROUP_CONCAT(DISTINCT mm.tactic || ' / ' || mm.technique_id || ' ' || mm.technique_name) AS mitre
                    FROM incidents i
                    LEFT JOIN incident_alerts ia ON ia.incident_id = i.incident_id
                    LEFT JOIN alerts a ON a.alert_id = ia.alert_id
                    LEFT JOIN mitre_mappings mm ON mm.alert_id = a.alert_id
                    GROUP BY i.incident_id
                    ORDER BY i.updated_at_utc DESC
                    LIMIT 150
                    """
                ).fetchall()
                incidents = []
                for row in rows:
                    metadata = _payload(row["metadata_json"])
                    risk_score = metadata.get("risk_score") or row["risk_score"] or ""
                    timeline = metadata.get("timeline") or []
                    timeline_text = (
                        " -> ".join(f"{item.get('time', '')}: {item.get('event', '')}" for item in timeline)
                        if isinstance(timeline, list)
                        else _short_time(row["opened_at_utc"])
                    )
                    evidence = metadata.get("evidence") or []
                    evidence_text = "; ".join(str(item) for item in evidence) if isinstance(evidence, list) else str(evidence)
                    incidents.append(
                        {
                        "incident_id": row["incident_id"],
                        "title": row["title"],
                        "severity": row["severity"],
                        "risk_score": risk_score,
                        "affected_device": row["owner"] or "",
                        "related_alerts": row["related_alerts"] or "",
                        "timeline": timeline_text,
                        "mitre_mapping": _mitre_text(row["mitre"]),
                        "evidence": evidence_text or row["summary"] or "",
                        "status": row["status"],
                        }
                    )
                return incidents
            if self._table_exists(conn, "alerts") and self._count(conn, "alerts") > 0:
                rows = conn.execute(
                    """
                    SELECT
                        a.device_id,
                        COUNT(a.alert_id) AS alert_count,
                        MAX(a.severity) AS severity,
                        MAX(a.risk_score) AS risk_score,
                        MIN(a.created_at_utc) AS first_seen,
                        MAX(a.created_at_utc) AS last_seen,
                        GROUP_CONCAT(a.alert_id, ', ') AS related_alerts,
                        GROUP_CONCAT(DISTINCT mm.tactic || ' / ' || mm.technique_id || ' ' || mm.technique_name) AS mitre
                    FROM alerts a
                    LEFT JOIN mitre_mappings mm ON mm.alert_id = a.alert_id
                    GROUP BY a.device_id
                    HAVING alert_count > 0
                    ORDER BY risk_score DESC, last_seen DESC
                    LIMIT 150
                    """
                ).fetchall()
                return [
                    {
                        "incident_id": f"CORR-{index:04d}",
                        "title": f"Correlated alerts on {row['device_id'] or 'Unknown'}",
                        "severity": row["severity"] or "info",
                        "risk_score": row["risk_score"],
                        "affected_device": row["device_id"] or "Unknown",
                        "related_alerts": row["related_alerts"] or "",
                        "timeline": f"{_short_time(row['first_seen'])} to {_short_time(row['last_seen'])}",
                        "mitre_mapping": _mitre_text(row["mitre"]),
                        "evidence": f"{row['alert_count']} related alert(s) on {row['device_id'] or 'Unknown'}",
                        "status": "open",
                    }
                    for index, row in enumerate(rows, start=1)
                ]
            if not self._table_exists(conn, "findings"):
                return []
            rows = conn.execute(
                """
                SELECT
                    se.asset_id,
                    COUNT(f.finding_id) AS alert_count,
                    MAX(f.severity) AS severity,
                    MAX(COALESCE(ra.score, 0)) AS risk_score,
                    MIN(f.created_at_utc) AS first_seen,
                    MAX(f.created_at_utc) AS last_seen,
                    GROUP_CONCAT(f.finding_id, ', ') AS related_alerts,
                    GROUP_CONCAT(DISTINCT mt.technique_id) AS mitre
                FROM findings f
                LEFT JOIN sensor_events se ON se.event_id = f.event_id
                LEFT JOIN risk_assessments ra ON ra.event_id = f.event_id
                LEFT JOIN finding_mitre_techniques fmt ON fmt.finding_id = f.finding_id
                LEFT JOIN mitre_techniques mt ON mt.technique_id = fmt.technique_id
                GROUP BY se.asset_id
                HAVING alert_count > 0
                ORDER BY risk_score DESC, last_seen DESC
                LIMIT 150
                """
            ).fetchall()
        incidents = []
        for index, row in enumerate(rows, start=1):
            device = row["asset_id"] or "Unknown"
            incidents.append(
                {
                    "incident_id": f"CORR-{index:04d}",
                    "title": f"Correlated findings on {device}",
                    "severity": row["severity"] or "info",
                    "risk_score": row["risk_score"],
                    "affected_device": device,
                    "related_alerts": row["related_alerts"] or "",
                    "timeline": f"{_short_time(row['first_seen'])} to {_short_time(row['last_seen'])}",
                    "mitre_mapping": _mitre_text(row["mitre"]),
                    "evidence": f"{row['alert_count']} related finding(s) on {device}",
                    "status": "open",
                }
            )
        return incidents

    def list_incidents(self) -> list[dict]:
        return self.get_incidents()

    def get_connections(self) -> list[dict]:
        with self._connect() as conn:
            if self._table_exists(conn, "connections") and self._count(conn, "connections") > 0:
                rows = conn.execute(
                    """
                    SELECT
                        c.last_seen_utc,
                        c.device_id,
                        c.protocol,
                        c.local_address,
                        c.local_port,
                        c.remote_address,
                        c.remote_port,
                        c.direction,
                        c.state,
                        c.metadata_json,
                        COALESCE(ra.score, 0) AS risk_score,
                        ra.reasons_json
                    FROM connections c
                    LEFT JOIN risk_assessments ra ON ra.event_id = c.event_id
                    ORDER BY c.last_seen_utc DESC
                    LIMIT 150
                    """
                ).fetchall()
                connections = []
                for row in rows:
                    metadata = _payload(row["metadata_json"])
                    connections.append(
                        {
                            "time": _short_time(row["last_seen_utc"]),
                            "process": metadata.get("process_name") or row["device_id"] or "Unknown",
                            "pid": metadata.get("process_id", ""),
                            "source_ip": row["local_address"] or "",
                            "destination_ip": row["remote_address"] or "",
                            "port": row["remote_port"] or "",
                            "protocol": row["protocol"] or "",
                            "direction": row["direction"] or "unknown",
                            "risk": row["risk_score"],
                            "basis": _reasons(row["reasons_json"]) or row["state"] or "",
                        }
                    )
                return connections
            if not self._table_exists(conn, "sensor_events"):
                return []
            rows = conn.execute(
                """
                SELECT se.timestamp_utc, se.asset_id, se.payload_json, COALESCE(ra.score, 0) AS risk_score, ra.reasons_json
                FROM sensor_events se
                LEFT JOIN risk_assessments ra ON ra.event_id = se.event_id
                WHERE se.event_type = 'network.connection_observed'
                ORDER BY se.timestamp_utc DESC
                LIMIT 150
                """
            ).fetchall()
        connections = []
        for row in rows:
            payload = _payload(row["payload_json"])
            local_ip = str(payload.get("local_address", ""))
            remote_ip = str(payload.get("remote_address", ""))
            connections.append(
                {
                    "time": _short_time(row["timestamp_utc"]),
                    "process": payload.get("process_name") or row["asset_id"] or "Unknown",
                    "pid": payload.get("process_id", ""),
                    "source_ip": local_ip,
                    "destination_ip": remote_ip,
                    "port": payload.get("remote_port", ""),
                    "protocol": payload.get("protocol", ""),
                    "direction": "outbound" if remote_ip and not remote_ip.startswith(("0.", "127.")) else "local",
                    "risk": row["risk_score"],
                    "basis": _reasons(row["reasons_json"]) or payload.get("state", ""),
                }
            )
        return connections

    def get_dns_logs(self) -> list[dict]:
        with self._connect() as conn:
            if self._table_exists(conn, "dns_logs") and self._count(conn, "dns_logs") > 0:
                rows = conn.execute(
                    """
                    SELECT timestamp_utc, device_id, query, record_type, response_code, risk_score, metadata_json
                    FROM dns_logs
                    ORDER BY timestamp_utc DESC
                    LIMIT 150
                    """
                ).fetchall()
                return [
                    {
                        "time": _short_time(row["timestamp_utc"]),
                        "device": row["device_id"] or "Unknown",
                        "query": row["query"],
                        "event_type": row["record_type"] or row["response_code"] or "dns.query",
                        "risk": row["risk_score"],
                        "basis": "DNS telemetry",
                    }
                    for row in rows
                ]
            if not self._table_exists(conn, "sensor_events"):
                return []
            rows = conn.execute(
                """
                SELECT se.timestamp_utc, se.asset_id, se.event_type, se.payload_json, COALESCE(ra.score, 0) AS risk_score
                FROM sensor_events se
                LEFT JOIN risk_assessments ra ON ra.event_id = se.event_id
                WHERE se.event_type LIKE 'dns.%'
                ORDER BY se.timestamp_utc DESC
                LIMIT 150
                """
            ).fetchall()
        logs = []
        for row in rows:
            payload = _payload(row["payload_json"])
            query = payload.get("query") or payload.get("domain") or payload.get("hostname") or payload.get("dns_query") or ""
            logs.append(
                {
                    "time": _short_time(row["timestamp_utc"]),
                    "device": row["asset_id"] or "Unknown",
                    "query": query,
                    "event_type": row["event_type"],
                    "risk": row["risk_score"],
                    "basis": "DNS telemetry",
                }
            )
        return logs

    def get_traffic_logs(self) -> list[dict]:
        with self._connect() as conn:
            if self._table_exists(conn, "traffic_logs") and self._count(conn, "traffic_logs") > 0:
                rows = conn.execute(
                    """
                    SELECT
                        timestamp_utc,
                        device_id,
                        source_address,
                        destination_address,
                        destination_port,
                        protocol,
                        bytes_sent,
                        bytes_received,
                        total_bytes,
                        direction,
                        metadata_json
                    FROM traffic_logs
                    ORDER BY timestamp_utc DESC
                    LIMIT 150
                    """
                ).fetchall()
                return [
                    {
                        "time": _short_time(row["timestamp_utc"]),
                        "device": row["device_id"] or "Unknown",
                        "event_type": row["protocol"] or "network",
                        "source": row["source_address"] or "",
                        "destination": row["destination_address"] or "",
                        "bytes": row["total_bytes"] or row["bytes_sent"] or row["bytes_received"] or "",
                        "basis": row["direction"] or "Sensor telemetry",
                    }
                    for row in rows
                ]
            if not self._table_exists(conn, "sensor_events"):
                return []
            rows = conn.execute(
                """
                SELECT timestamp_utc, asset_id, event_type, payload_json
                FROM sensor_events
                WHERE event_type NOT IN ('network.connection_observed')
                  AND event_type NOT LIKE 'dns.%'
                  AND event_type LIKE 'network.%'
                ORDER BY timestamp_utc DESC
                LIMIT 150
                """
            ).fetchall()
        samples = []
        for row in rows:
            payload = _payload(row["payload_json"])
            samples.append(
                {
                    "time": _short_time(row["timestamp_utc"]),
                    "device": row["asset_id"] or "Unknown",
                    "event_type": row["event_type"],
                    "source": payload.get("source") or payload.get("local_address", ""),
                    "destination": payload.get("destination") or payload.get("remote_address", ""),
                    "bytes": payload.get("bytes", ""),
                    "basis": "Sensor telemetry",
                }
            )
        return samples

    def list_reports(self) -> list[dict]:
        with self._connect() as conn:
            rows = []
            if self._table_exists(conn, "reports"):
                rows = conn.execute(
                    "SELECT title, report_type, status, generated_at_utc FROM reports ORDER BY generated_at_utc DESC LIMIT 150"
                ).fetchall()
                return [
                    {
                        "title": row["title"],
                        "type": row["report_type"],
                        "status": row["status"],
                        "updated": _short_time(row["generated_at_utc"]),
                    }
                    for row in rows
                ]
            if self._table_exists(conn, "report_artifacts"):
                rows = conn.execute(
                    "SELECT title, report_type, created_at_utc FROM report_artifacts ORDER BY created_at_utc DESC LIMIT 150"
                ).fetchall()
        return [
            {"title": row["title"], "type": row["report_type"], "status": "generated", "updated": _short_time(row["created_at_utc"])}
            for row in rows
        ]

    def threat_timeline(self) -> list[dict]:
        rows = self.get_alerts()[:20]
        return [
            {
                "time": row["time"],
                "event": row["basis_evidence"],
                "device": row["device_host"],
                "details": f"{row.get('severity', '').upper()} | Risk {row.get('risk_score', '')} | {row.get('mitre', '')}",
            }
            for row in rows
        ]

    def get_debug_status(self) -> dict:
        with self._connect() as conn:
            sensor_events = self._count(conn, "sensor_events")
            findings = self._count(conn, "findings")
            lan_devices = self._count(conn, "lan_devices")
            last_seen = self._scalar(conn, "SELECT MAX(timestamp_utc) FROM sensor_events", default="")
        return {
            "sensor_status": "Receiving telemetry" if sensor_events else "No sensor telemetry yet",
            "database_status": "Connected" if self.db_path.exists() else "Database not created",
            "last_telemetry_received": _short_time(last_seen) if last_seen else "None",
            "last_dashboard_refresh": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rows_loaded": str(sensor_events + findings + lan_devices),
            "status": "Healthy" if self.db_path.exists() else "Warning",
            "uptime": "Current session",
        }

    def run_validation_test(self, test_key: str) -> dict:
        result = self.validation_simulator.run_test(test_key)
        self.ai_report_intelligence.save_validation_result(result)
        return result

    def generate_ai_security_summary(self, settings: dict | None = None, scope: str = "all") -> dict:
        report = self.ai_report_intelligence.generate_ai_security_summary(
            settings=AIAnalystSettings(**(settings or {})),
            scope=scope,
        )
        outputs = self.ai_report_intelligence.save_report(report)
        return {
            "text": report.to_text(),
            "outputs": outputs,
            "mode_used": report.mode_used,
            "generated_at": report.generated_at,
        }
