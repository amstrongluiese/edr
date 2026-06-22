from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from .config import ARCHIVE_DIR
from .db import connect, fetch_all, fetch_one, json_dumps, utc_now


_CURRENT_SESSION_ID: str | None = None

SESSION_TABLES = [
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
]


def get_current_session_id() -> str | None:
    return _CURRENT_SESSION_ID


def set_current_session_id(session_id: str | None) -> None:
    global _CURRENT_SESSION_ID
    _CURRENT_SESSION_ID = session_id


def start_session() -> str:
    session_id = uuid.uuid4().hex[:12]
    set_current_session_id(session_id)
    with connect() as conn:
        conn.execute(
            "INSERT INTO sessions(session_id, started_at, status) VALUES (?, ?, 'running')",
            (session_id, utc_now()),
        )
    return session_id


def _table_rows(table: str, session_id: str) -> list[dict[str, Any]]:
    rows = fetch_all(f"SELECT * FROM {table} WHERE session_id = ? ORDER BY id", (session_id,))
    return [dict(row) for row in rows]


def archive_session(session_id: str) -> Path:
    archive_dir = ARCHIVE_DIR / f"session_{session_id}"
    archive_dir.mkdir(parents=True, exist_ok=True)

    summary = build_session_summary(session_id)
    (archive_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (archive_dir / "logs.jsonl").write_text(
        "\n".join(json.dumps(row, sort_keys=True) for table in ["session_events", "log_events", "dns_logs", "connections"] for row in _table_rows(table, session_id)) + "\n",
        encoding="utf-8",
    )
    (archive_dir / "technical_report.json").write_text(
        json.dumps({table: _table_rows(table, session_id) for table in ["devices", "connections", "alerts", "incidents", "dns_logs", "file_events", "process_events"]}, indent=2),
        encoding="utf-8",
    )
    (archive_dir / "validation_report.json").write_text(
        json.dumps(
            {
                "validation_results": _table_rows("validation_results", session_id),
                "testing_verification": _table_rows("testing_verification", session_id),
                "summary": summary,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    try:
        from .ai_analyst import generate_analysis

        analysis = generate_analysis(session_id=session_id)
    except Exception as exc:
        analysis = f"AI analysis unavailable: {exc}"
    (archive_dir / "ai_analysis_report.txt").write_text(analysis, encoding="utf-8")
    return archive_dir


def build_session_summary(session_id: str) -> dict[str, Any]:
    devices = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE session_id = ? AND is_inventory_device = 1", (session_id,))
    alerts = fetch_one("SELECT COUNT(*) AS count FROM alerts WHERE session_id = ?", (session_id,))
    incidents = fetch_one("SELECT COUNT(*) AS count FROM incidents WHERE session_id = ?", (session_id,))
    outcomes = {key: 0 for key in ["TP", "TN", "FP", "FN"]}
    for row in fetch_all("SELECT outcome FROM validation_results WHERE session_id = ?", (session_id,)):
        outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1
    total = sum(outcomes.values())
    accuracy = (outcomes["TP"] + outcomes["TN"]) / total if total else None
    fpr = outcomes["FP"] / (outcomes["FP"] + outcomes["TN"]) if (outcomes["FP"] + outcomes["TN"]) else None
    fnr = outcomes["FN"] / (outcomes["FN"] + outcomes["TP"]) if (outcomes["FN"] + outcomes["TP"]) else None
    response_rows = fetch_all("SELECT response_ms FROM validation_results WHERE session_id = ?", (session_id,))
    if not response_rows:
        response_rows = fetch_all("SELECT detection_time_ms AS response_ms FROM testing_verification WHERE session_id = ?", (session_id,))
    avg_response = sum(float(row["response_ms"]) for row in response_rows) / len(response_rows) if response_rows else None
    cpu_rows = fetch_all("SELECT metric_value FROM performance_metrics WHERE session_id = ? AND metric_name LIKE 'cpu%'", (session_id,))
    mem_rows = fetch_all("SELECT metric_value FROM performance_metrics WHERE session_id = ? AND metric_name = 'memory_usage'", (session_id,))
    cpu_avg = sum(float(row["metric_value"]) for row in cpu_rows) / len(cpu_rows) if cpu_rows else None
    memory_avg = sum(float(row["metric_value"]) for row in mem_rows) / len(mem_rows) if mem_rows else None
    session = fetch_one("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    return {
        "session_id": session_id,
        "started_at": session["started_at"] if session else None,
        "stopped_at": session["stopped_at"] if session else None,
        "status": session["status"] if session else "unknown",
        "total_devices": int(devices["count"] if devices else 0),
        "total_alerts": int(alerts["count"] if alerts else 0),
        "total_incidents": int(incidents["count"] if incidents else 0),
        "validation": {**outcomes, "accuracy": accuracy, "false_positive_rate": fpr, "false_negative_rate": fnr, "avg_response_time": avg_response},
        "performance": {"cpu_avg": cpu_avg, "memory_avg": memory_avg},
    }


def stop_session(session_id: str) -> Path:
    stopped_at = utc_now()
    with connect() as conn:
        conn.execute("UPDATE sessions SET stopped_at = ?, status = 'stopping' WHERE session_id = ?", (stopped_at, session_id))
    archive_dir = archive_session(session_id)
    summary = build_session_summary(session_id)
    with connect() as conn:
        conn.execute(
            """
            UPDATE sessions
            SET stopped_at = ?, status = 'stopped', total_devices = ?, total_alerts = ?,
                total_incidents = ?, detection_accuracy = ?, false_positive_rate = ?,
                false_negative_rate = ?, avg_response_time = ?, cpu_avg = ?, memory_avg = ?,
                archive_path = ?
            WHERE session_id = ?
            """,
            (
                stopped_at,
                summary["total_devices"],
                summary["total_alerts"],
                summary["total_incidents"],
                summary["validation"]["accuracy"],
                summary["validation"]["false_positive_rate"],
                summary["validation"]["false_negative_rate"],
                summary["validation"]["avg_response_time"],
                summary["performance"]["cpu_avg"],
                summary["performance"]["memory_avg"],
                str(archive_dir),
                session_id,
            ),
        )
    if get_current_session_id() == session_id:
        set_current_session_id(None)
    return archive_dir


def session_filter(alias: str = "") -> tuple[str, tuple[Any, ...]]:
    session_id = get_current_session_id()
    prefix = f"{alias}." if alias else ""
    if not session_id:
        return "1 = 0", ()
    return f"{prefix}session_id = ?", (session_id,)


def active_session_status() -> str:
    if not get_current_session_id():
        return "Monitoring Not Started"
    return "Monitoring Active"
