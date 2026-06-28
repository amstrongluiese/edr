from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from edr_engine.ai_analyst.models import AnalystAlert, AnalystIncident, AnalystInput, MitreMapping, ThreatIntelMatch


def _payload(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


class SQLiteAnalystContextLoader:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def load(self, subject: str = "Current environment") -> AnalystInput:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            alerts = self._load_alerts(conn)
            incidents = self._load_incidents(conn)
            mappings = self._load_mitre_mappings(conn)
            intel_matches = self._load_threat_intel_matches(conn)

        risk_scores = [alert.risk_score for alert in alerts] + [incident.risk_score for incident in incidents]
        risk_score = max(risk_scores) if risk_scores else 0
        return AnalystInput(
            subject=subject,
            risk_score=risk_score,
            alerts=alerts,
            incidents=incidents,
            mitre_mappings=mappings,
            threat_intel_matches=intel_matches,
        )

    def _load_alerts(self, conn: sqlite3.Connection) -> list[AnalystAlert]:
        if not self._table_exists(conn, "alerts"):
            return []
        rows = conn.execute(
            """
            SELECT alert_id, title, severity, device_id, risk_score, COALESCE(description, '') AS description, metadata_json
            FROM alerts
            ORDER BY created_at_utc DESC
            LIMIT 200
            """
        ).fetchall()
        return [
            AnalystAlert(
                alert_id=row["alert_id"],
                title=row["title"],
                severity=row["severity"],
                device_id=row["device_id"],
                risk_score=int(row["risk_score"] or 0),
                description=row["description"],
                metadata=_payload(row["metadata_json"]),
            )
            for row in rows
        ]

    def _load_incidents(self, conn: sqlite3.Connection) -> list[AnalystIncident]:
        if not self._table_exists(conn, "incidents"):
            return []
        rows = conn.execute(
            """
            SELECT incident_id, title, severity, status, owner, metadata_json
            FROM incidents
            ORDER BY updated_at_utc DESC
            LIMIT 100
            """
        ).fetchall()
        incidents = []
        for row in rows:
            metadata = _payload(row["metadata_json"])
            incidents.append(
                AnalystIncident(
                    incident_id=row["incident_id"],
                    title=row["title"],
                    severity=row["severity"],
                    risk_score=int(metadata.get("risk_score") or 0),
                    affected_device=row["owner"] or "Unknown",
                    timeline=metadata.get("timeline", []) if isinstance(metadata.get("timeline"), list) else [],
                    evidence=metadata.get("evidence", []) if isinstance(metadata.get("evidence"), list) else [],
                    related_alert_ids=metadata.get("alert_ids", []) if isinstance(metadata.get("alert_ids"), list) else [],
                    status=row["status"],
                    metadata=metadata,
                )
            )
        return incidents

    def _load_mitre_mappings(self, conn: sqlite3.Connection) -> list[MitreMapping]:
        if not self._table_exists(conn, "mitre_mappings"):
            return []
        rows = conn.execute(
            """
            SELECT DISTINCT technique_id, technique_name, tactic, confidence
            FROM mitre_mappings
            ORDER BY tactic, technique_id
            """
        ).fetchall()
        return [
            MitreMapping(
                technique_id=row["technique_id"],
                technique_name=row["technique_name"],
                tactic=row["tactic"],
                confidence=row["confidence"],
            )
            for row in rows
        ]

    def _load_threat_intel_matches(self, conn: sqlite3.Connection) -> list[ThreatIntelMatch]:
        if not self._table_exists(conn, "threat_intel_matches"):
            return []
        rows = conn.execute(
            """
            SELECT observable_value, observable_kind, source, reputation, metadata_json
            FROM threat_intel_matches
            ORDER BY matched_at_utc DESC
            LIMIT 100
            """
        ).fetchall()
        matches = []
        for row in rows:
            metadata = _payload(row["metadata_json"])
            matches.append(
                ThreatIntelMatch(
                    observable=row["observable_value"],
                    observable_type=row["observable_kind"],
                    source=row["source"],
                    reputation=row["reputation"],
                    summary=str(metadata.get("basis") or metadata.get("summary") or ""),
                    metadata=metadata,
                )
            )
        return matches

    def _table_exists(self, conn: sqlite3.Connection, table: str) -> bool:
        row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
        return row is not None
