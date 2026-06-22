import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable

from .config import DATA_DIR, DB_PATH


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@contextmanager
def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                stopped_at TEXT,
                status TEXT NOT NULL,
                total_devices INTEGER NOT NULL DEFAULT 0,
                total_alerts INTEGER NOT NULL DEFAULT 0,
                total_incidents INTEGER NOT NULL DEFAULT 0,
                detection_accuracy REAL,
                false_positive_rate REAL,
                false_negative_rate REAL,
                avg_response_time REAL,
                cpu_avg REAL,
                memory_avg REAL,
                archive_path TEXT
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                mac TEXT,
                hostname TEXT,
                vendor TEXT,
                device_type TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                trust_status TEXT NOT NULL DEFAULT 'unknown',
                risk_level TEXT NOT NULL DEFAULT 'Informational',
                risk_score INTEGER NOT NULL DEFAULT 0,
                online_status TEXT NOT NULL DEFAULT 'unknown',
                discovery_source TEXT NOT NULL DEFAULT 'telemetry',
                device_key TEXT,
                is_inventory_device INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                process_name TEXT,
                pid INTEGER,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                port INTEGER,
                protocol TEXT,
                direction TEXT,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                event_type TEXT NOT NULL,
                raw_event TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dns_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                domain TEXT NOT NULL,
                query_type TEXT,
                resolved_ip TEXT,
                raw_event TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                bytes_total INTEGER NOT NULL,
                window_seconds INTEGER NOT NULL,
                raw_event TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                alert_type TEXT NOT NULL,
                entity TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                evidence TEXT NOT NULL,
                evidence_hash TEXT,
                reason TEXT NOT NULL,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                mitre_id TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'open'
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                alert_ids TEXT NOT NULL,
                evidence TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
            );

            CREATE TABLE IF NOT EXISTS mitre_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_type TEXT NOT NULL UNIQUE,
                tactic TEXT NOT NULL,
                technique TEXT NOT NULL,
                attack_id TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                report_type TEXT NOT NULL,
                path TEXT NOT NULL,
                summary TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                test_name TEXT NOT NULL,
                expected_malicious INTEGER NOT NULL,
                detected_malicious INTEGER NOT NULL,
                outcome TEXT NOT NULL,
                response_ms REAL NOT NULL,
                alert_ids TEXT NOT NULL,
                notes TEXT NOT NULL,
                validation_run_id TEXT
            );

            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                indicator_type TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                details TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                unit TEXT NOT NULL,
                context TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                item_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                evidence TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'recorded'
            );

            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                path TEXT NOT NULL,
                extension TEXT,
                sha256 TEXT,
                signed_status TEXT,
                source TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                evidence TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                process_name TEXT,
                pid INTEGER,
                parent_process TEXT,
                command_line TEXT,
                executable_path TEXT,
                sha256 TEXT,
                signed_status TEXT,
                source TEXT NOT NULL,
                evidence TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                log_source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                device TEXT,
                target_system TEXT,
                outcome TEXT,
                raw_event TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS failed_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                device TEXT,
                target_system TEXT,
                failed_count INTEGER NOT NULL,
                window_seconds INTEGER NOT NULL,
                evidence_logs TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
            );

            CREATE TABLE IF NOT EXISTS cve_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                cvss REAL NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                entity TEXT,
                severity TEXT NOT NULL DEFAULT 'Informational',
                evidence TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS testing_verification (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TEXT NOT NULL,
                test_name TEXT NOT NULL,
                expected_result TEXT NOT NULL,
                actual_result TEXT NOT NULL,
                pass_fail TEXT NOT NULL,
                outcome TEXT NOT NULL,
                detection_time_ms REAL NOT NULL,
                evidence TEXT NOT NULL
            );
            """
        )
        _ensure_column(conn, "devices", "online_status", "TEXT NOT NULL DEFAULT 'unknown'")
        _ensure_column(conn, "devices", "discovery_source", "TEXT NOT NULL DEFAULT 'telemetry'")
        _ensure_column(conn, "devices", "device_key", "TEXT")
        _ensure_column(conn, "devices", "is_inventory_device", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "validation_results", "validation_run_id", "TEXT")
        _ensure_column(conn, "alerts", "first_seen", "TEXT")
        _ensure_column(conn, "alerts", "last_seen", "TEXT")
        _ensure_column(conn, "alerts", "evidence_hash", "TEXT")
        _ensure_column(conn, "alerts", "occurrence_count", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "connections", "source_port", "INTEGER")
        _ensure_column(conn, "connections", "direction", "TEXT")
        for table in [
            "devices",
            "connections",
            "alerts",
            "incidents",
            "dns_logs",
            "traffic_logs",
            "scan_results",
            "file_events",
            "process_events",
            "log_events",
            "failed_attempts",
            "cve_matches",
            "validation_results",
            "performance_metrics",
            "reports",
            "session_events",
            "testing_verification",
        ]:
            _ensure_column(conn, table, "session_id", "TEXT")
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_devices_inventory ON devices(is_inventory_device, online_status, risk_score);
            CREATE INDEX IF NOT EXISTS idx_devices_key ON devices(device_key);
            CREATE INDEX IF NOT EXISTS idx_alerts_group ON alerts(alert_type, entity, evidence_hash, status);
            CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen);
            CREATE INDEX IF NOT EXISTS idx_session_events_session ON session_events(session_id, timestamp, event_type);
            CREATE INDEX IF NOT EXISTS idx_testing_session ON testing_verification(session_id, timestamp);
            """
        )


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise


def fetch_all(sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(conn.execute(sql, tuple(params)).fetchall())


def fetch_one(sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute(sql, tuple(params)).fetchone()


def execute(sql: str, params: Iterable[Any] = ()) -> int:
    with connect() as conn:
        cur = conn.execute(sql, tuple(params))
        return int(cur.lastrowid or 0)


def record_metric(name: str, value: float, unit: str, context: dict[str, Any] | None = None) -> None:
    from .sessions import get_current_session_id

    execute(
        """
        INSERT INTO performance_metrics(timestamp, metric_name, metric_value, unit, context, session_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (utc_now(), name, value, unit, json_dumps(context or {}), get_current_session_id()),
    )
