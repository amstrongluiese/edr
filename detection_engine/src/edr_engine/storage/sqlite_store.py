from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from edr_engine.correlation.incidents import AlertCorrelationRecord, IncidentCorrelationEngine
from edr_engine.core.events import DetectionAlert, DetectionFinding, RiskAssessment, SensorEvent
from edr_engine.engine import MitreRepository
from edr_engine.mitre.interfaces import MitreMapper
from edr_engine.threat_intel.interfaces import IntelResult, Observable


def dt_to_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def int_or_zero(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


class SQLiteStore(MitreRepository):
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._incident_correlator = IncidentCorrelationEngine()

    def close(self) -> None:
        self._conn.close()

    def apply_migrations(self, migrations_dir: Path) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at_utc TEXT NOT NULL
            )
            """
        )

        for migration in sorted(migrations_dir.glob("*.sql")):
            version = migration.stem
            applied = self._conn.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?",
                (version,),
            ).fetchone()
            if applied:
                continue
            self._conn.executescript(migration.read_text(encoding="utf-8"))
            self._conn.execute(
                "INSERT INTO schema_migrations (version, applied_at_utc) VALUES (?, ?)",
                (version, dt_to_text(datetime.now(timezone.utc))),
            )
            self._conn.commit()

    def exists(self, asset_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM assets WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()
        return row is not None

    def upsert_seen(self, event: SensorEvent) -> None:
        now = dt_to_text(event.timestamp_utc)
        self._conn.execute(
            """
            INSERT INTO assets (asset_id, hostname, platform, first_seen_utc, last_seen_utc)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(asset_id) DO UPDATE SET last_seen_utc = excluded.last_seen_utc
            """,
            (event.asset_id, event.asset_id, "windows", now, now),
        )
        self._conn.commit()

    def save_event(self, event: SensorEvent) -> None:
        self._conn.execute(
            """
            INSERT OR IGNORE INTO assets (asset_id, hostname, platform, first_seen_utc, last_seen_utc)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event.asset_id,
                event.asset_id,
                "windows",
                dt_to_text(event.timestamp_utc),
                dt_to_text(event.timestamp_utc),
            ),
        )
        self._conn.execute(
            """
            INSERT OR IGNORE INTO sensor_events (
                event_id,
                schema_version,
                event_type,
                asset_id,
                timestamp_utc,
                source,
                payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.schema_version,
                event.event_type,
                event.asset_id,
                dt_to_text(event.timestamp_utc),
                event.source,
                json.dumps(event.payload, sort_keys=True),
            ),
        )
        self._upsert_device_from_event(event)
        self._save_operational_event(event)
        self._conn.commit()

    def save_finding(self, finding: DetectionFinding) -> None:
        self._conn.execute(
            """
            INSERT OR IGNORE INTO findings (
                finding_id,
                event_id,
                provider_id,
                title,
                severity,
                metadata_json,
                created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.finding_id,
                finding.event_id,
                finding.provider_id,
                finding.title,
                finding.severity,
                json.dumps(finding.metadata, sort_keys=True),
                dt_to_text(datetime.now(timezone.utc)),
            ),
        )
        self._conn.commit()

    def save_risk(self, risk: RiskAssessment) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO risk_assessments (
                risk_id,
                event_id,
                asset_id,
                score,
                severity,
                reasons_json,
                created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                risk.risk_id,
                risk.event_id,
                risk.asset_id,
                risk.score,
                risk.severity,
                json.dumps(risk.reasons),
                dt_to_text(risk.created_at_utc),
            ),
        )
        self._conn.commit()

    def save_alert(self, alert: DetectionAlert) -> None:
        now = dt_to_text(alert.created_at_utc)
        self._conn.execute(
            """
            INSERT OR IGNORE INTO devices (
                device_id,
                asset_id,
                hostname,
                platform,
                risk_score,
                status,
                first_seen_utc,
                last_seen_utc,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                risk_score = MAX(risk_score, excluded.risk_score),
                last_seen_utc = excluded.last_seen_utc
            """,
            (
                alert.device_id,
                alert.device_id,
                alert.device_id,
                "windows",
                alert.risk_score,
                "online",
                now,
                now,
                "{}",
            ),
        )
        self._conn.execute(
            """
            INSERT OR IGNORE INTO alerts (
                alert_id,
                finding_id,
                device_id,
                event_id,
                title,
                description,
                severity,
                risk_score,
                status,
                provider_id,
                created_at_utc,
                updated_at_utc,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert.finding_id,
                alert.device_id,
                alert.event_id,
                alert.title,
                alert.description,
                alert.severity,
                alert.risk_score,
                "open",
                alert.provider_id,
                now,
                now,
                json.dumps(alert.metadata, sort_keys=True),
            ),
        )
        self._save_threat_intel_match(alert)
        self._conn.commit()

    def lookup_threat_intel(self, observables: list[Observable]) -> list[IntelResult]:
        if not observables or not self._table_exists("threat_intelligence"):
            return []

        results: list[IntelResult] = []
        now = dt_to_text(datetime.now(timezone.utc))
        for observable in observables:
            rows = self._conn.execute(
                """
                SELECT
                    indicator_id,
                    observable_value,
                    observable_kind,
                    source,
                    reputation,
                    confidence,
                    summary,
                    cve_id,
                    cve_severity,
                    metadata_json
                FROM threat_intelligence
                WHERE observable_kind = ?
                  AND observable_value = ?
                  AND (expires_at_utc IS NULL OR expires_at_utc > ?)
                ORDER BY
                    CASE reputation
                        WHEN 'malicious' THEN 1
                        WHEN 'suspicious' THEN 2
                        WHEN 'unknown' THEN 3
                        ELSE 4
                    END,
                    confidence DESC
                """,
                (observable.kind, observable.value, now),
            ).fetchall()
            for row in rows:
                metadata = self._json(row[9])
                metadata.update(
                    {
                        "indicator_id": row[0],
                        "summary": row[6] or "",
                        "confidence": int_or_zero(row[5]),
                        "cve_id": row[7] or "",
                        "cve_severity": row[8] or "",
                    }
                )
                results.append(
                    IntelResult(
                        observable=Observable(value=str(row[1]), kind=str(row[2])),
                        source=str(row[3]),
                        reputation=str(row[4]),
                        metadata=metadata,
                    )
                )
        return results

    def lookup_cve_matches(self, event: SensorEvent) -> list[dict]:
        if not self._table_exists("threat_intelligence"):
            return []

        explicit_cves = {
            str(value).upper()
            for key, value in event.payload.items()
            if "cve" in key.lower() and str(value).upper().startswith("CVE-")
        }
        software_terms = self._software_terms(event)
        matches: list[dict] = []

        rows = self._conn.execute(
            """
            SELECT indicator_id, observable_value, source, summary, cve_id, cve_severity, metadata_json
            FROM threat_intelligence
            WHERE observable_kind = 'cve'
            """
        ).fetchall()
        for row in rows:
            metadata = self._json(row[6])
            cve_id = str(row[4] or row[1] or "").upper()
            haystack = " ".join(
                [
                    str(row[1] or ""),
                    str(row[3] or ""),
                    json.dumps(metadata, sort_keys=True),
                ]
            ).lower()
            matched_text = ""
            if cve_id in explicit_cves:
                matched_text = cve_id
            elif software_terms:
                for term in software_terms:
                    if term.lower() in haystack:
                        matched_text = term
                        break
            if not matched_text:
                continue
            matches.append(
                {
                    "indicator_id": row[0],
                    "observable_value": row[1],
                    "observable_kind": "cve",
                    "source": row[2],
                    "summary": row[3],
                    "cve_id": cve_id,
                    "cve_severity": row[5] or metadata.get("cve_severity", ""),
                    "cvss_score": metadata.get("cvss_score", 0),
                    "matched_text": matched_text,
                    "metadata": metadata,
                }
            )
        return matches

    def correlate_alerts(self, alerts: list[DetectionAlert]) -> None:
        device_ids = sorted({alert.device_id for alert in alerts})
        for device_id in device_ids:
            records = self._load_open_alert_records(device_id)
            for incident in self._incident_correlator.correlate(device_id, records):
                metadata = {
                    "risk_score": incident.risk_score,
                    "timeline": incident.timeline,
                    "evidence": incident.evidence,
                    "alert_ids": incident.alert_ids,
                    "categories": incident.categories,
                    "correlation_rule": incident.correlation_rule,
                }
                self._conn.execute(
                    """
                    INSERT INTO incidents (
                        incident_id,
                        title,
                        summary,
                        severity,
                        status,
                        owner,
                        opened_at_utc,
                        updated_at_utc,
                        metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        title = excluded.title,
                        summary = excluded.summary,
                        severity = excluded.severity,
                        status = excluded.status,
                        owner = excluded.owner,
                        updated_at_utc = excluded.updated_at_utc,
                        metadata_json = excluded.metadata_json
                    """,
                    (
                        incident.incident_id,
                        incident.title,
                        incident.summary,
                        incident.severity,
                        "open",
                        incident.device_id,
                        incident.opened_at_utc,
                        incident.updated_at_utc,
                        json.dumps(metadata, sort_keys=True),
                    ),
                )
                for alert_id in incident.alert_ids:
                    self._conn.execute(
                        """
                        INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, linked_at_utc)
                        VALUES (?, ?, ?)
                        """,
                        (incident.incident_id, alert_id, incident.updated_at_utc),
                    )
        self._conn.commit()

    def _load_open_alert_records(self, device_id: str) -> list[AlertCorrelationRecord]:
        rows = self._conn.execute(
            """
            SELECT
                alert_id,
                device_id,
                title,
                COALESCE(description, '') AS description,
                severity,
                risk_score,
                created_at_utc,
                metadata_json
            FROM alerts
            WHERE device_id = ?
              AND status IN ('open', 'triaged', 'in_progress')
            ORDER BY created_at_utc
            """,
            (device_id,),
        ).fetchall()
        records = []
        for row in rows:
            try:
                metadata = json.loads(row[7] or "{}")
            except json.JSONDecodeError:
                metadata = {}
            records.append(
                AlertCorrelationRecord(
                    alert_id=str(row[0]),
                    device_id=str(row[1]),
                    title=str(row[2]),
                    description=str(row[3]),
                    severity=str(row[4]),
                    risk_score=int(row[5] or 0),
                    created_at_utc=str(row[6]),
                    category=str(metadata.get("category", "")),
                )
            )
        return records

    def _upsert_device_from_event(self, event: SensorEvent) -> None:
        timestamp = dt_to_text(event.timestamp_utc)
        self._conn.execute(
            """
            INSERT OR IGNORE INTO devices (
                device_id,
                asset_id,
                hostname,
                platform,
                risk_score,
                status,
                first_seen_utc,
                last_seen_utc,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                last_seen_utc = excluded.last_seen_utc,
                status = CASE
                    WHEN devices.status = 'isolated' THEN devices.status
                    ELSE excluded.status
                END
            """,
            (
                event.asset_id,
                event.asset_id,
                event.asset_id,
                "windows",
                0,
                "online",
                timestamp,
                timestamp,
                "{}",
            ),
        )

    def _save_operational_event(self, event: SensorEvent) -> None:
        if event.event_type in {"process.created", "process.terminated"}:
            self._save_process_event(event)
        if event.event_type == "network.connection_observed":
            self._save_connection_event(event)
        if event.event_type.startswith("dns."):
            self._save_dns_event(event)
        if event.event_type.startswith("network."):
            self._save_traffic_event(event)

    def _save_process_event(self, event: SensorEvent) -> None:
        pid = int_or_zero(event.payload.get("process_id"))
        if pid <= 0:
            return
        process_id = f"{event.asset_id}:{pid}"
        timestamp = dt_to_text(event.timestamp_utc)
        if event.event_type == "process.terminated":
            cursor = self._conn.execute(
                """
                UPDATE processes
                SET ended_at_utc = ?, status = 'terminated', metadata_json = ?
                WHERE process_record_id = ?
                """,
                (timestamp, json.dumps(event.payload, sort_keys=True), process_id),
            )
            if cursor.rowcount:
                return

        image_name = str(event.payload.get("image_name") or event.payload.get("process_name") or "Unknown")
        self._conn.execute(
            """
            INSERT OR IGNORE INTO processes (
                process_record_id,
                device_id,
                event_id,
                process_id,
                parent_process_id,
                image_name,
                image_path,
                command_line,
                user_name,
                integrity_level,
                hash_sha256,
                started_at_utc,
                ended_at_utc,
                status,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                process_id,
                event.asset_id,
                event.event_id,
                pid,
                int_or_zero(event.payload.get("parent_process_id")) or None,
                image_name,
                str(event.payload.get("image_path") or ""),
                str(event.payload.get("command_line") or ""),
                str(event.payload.get("user_name") or ""),
                str(event.payload.get("integrity_level") or ""),
                str(event.payload.get("hash_sha256") or event.payload.get("sha256") or ""),
                timestamp,
                timestamp if event.event_type == "process.terminated" else None,
                "terminated" if event.event_type == "process.terminated" else "running",
                json.dumps(event.payload, sort_keys=True),
            ),
        )

    def _save_connection_event(self, event: SensorEvent) -> None:
        timestamp = dt_to_text(event.timestamp_utc)
        remote_address = str(event.payload.get("remote_address") or "")
        local_address = str(event.payload.get("local_address") or "")
        remote_port = int_or_zero(event.payload.get("remote_port"))
        direction = self._direction(local_address, remote_address)
        self._conn.execute(
            """
            INSERT OR IGNORE INTO connections (
                connection_id,
                device_id,
                process_record_id,
                event_id,
                protocol,
                local_address,
                local_port,
                remote_address,
                remote_port,
                remote_hostname,
                direction,
                state,
                first_seen_utc,
                last_seen_utc,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"conn-{event.event_id}",
                event.asset_id,
                None,
                event.event_id,
                str(event.payload.get("protocol") or "tcp"),
                local_address,
                int_or_zero(event.payload.get("local_port")) or None,
                remote_address,
                remote_port or None,
                str(event.payload.get("remote_hostname") or ""),
                direction,
                str(event.payload.get("state") or ""),
                timestamp,
                timestamp,
                json.dumps(event.payload, sort_keys=True),
            ),
        )

    def _save_dns_event(self, event: SensorEvent) -> None:
        query = (
            event.payload.get("query")
            or event.payload.get("domain")
            or event.payload.get("hostname")
            or event.payload.get("dns_query")
            or ""
        )
        if not query:
            return
        self._conn.execute(
            """
            INSERT OR IGNORE INTO dns_logs (
                dns_log_id,
                event_id,
                device_id,
                timestamp_utc,
                query,
                answer,
                record_type,
                response_code,
                risk_score,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"dns-{event.event_id}",
                event.event_id,
                event.asset_id,
                dt_to_text(event.timestamp_utc),
                str(query).strip(".").lower(),
                str(event.payload.get("answer") or event.payload.get("resolved_address") or ""),
                str(event.payload.get("record_type") or ""),
                str(event.payload.get("response_code") or ""),
                0,
                json.dumps(event.payload, sort_keys=True),
            ),
        )

    def _save_traffic_event(self, event: SensorEvent) -> None:
        bytes_sent = int_or_zero(
            event.payload.get("bytes_sent")
            or event.payload.get("bytes_out")
            or event.payload.get("outbound_bytes")
            or event.payload.get("upload_bytes")
        )
        bytes_received = int_or_zero(
            event.payload.get("bytes_received")
            or event.payload.get("bytes_in")
            or event.payload.get("inbound_bytes")
            or event.payload.get("download_bytes")
        )
        total_bytes = int_or_zero(event.payload.get("total_bytes") or event.payload.get("bytes"))
        if total_bytes <= 0:
            total_bytes = bytes_sent + bytes_received
        source_address = str(event.payload.get("source") or event.payload.get("local_address") or "")
        destination_address = str(event.payload.get("destination") or event.payload.get("remote_address") or "")
        self._conn.execute(
            """
            INSERT OR IGNORE INTO traffic_logs (
                traffic_log_id,
                event_id,
                device_id,
                timestamp_utc,
                source_address,
                source_port,
                destination_address,
                destination_port,
                protocol,
                bytes_sent,
                bytes_received,
                total_bytes,
                direction,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"traffic-{event.event_id}",
                event.event_id,
                event.asset_id,
                dt_to_text(event.timestamp_utc),
                source_address,
                int_or_zero(event.payload.get("source_port") or event.payload.get("local_port")) or None,
                destination_address,
                int_or_zero(event.payload.get("destination_port") or event.payload.get("remote_port")) or None,
                str(event.payload.get("protocol") or ""),
                bytes_sent,
                bytes_received,
                total_bytes,
                self._direction(source_address, destination_address),
                json.dumps(event.payload, sort_keys=True),
            ),
        )

    def _save_threat_intel_match(self, alert: DetectionAlert) -> None:
        metadata = alert.metadata
        intel = metadata.get("threat_intel")
        if not isinstance(intel, dict):
            return
        indicator_id = str(intel.get("indicator_id") or "")
        if not indicator_id:
            return
        self._conn.execute(
            """
            INSERT OR IGNORE INTO threat_intel_matches (
                match_id,
                event_id,
                alert_id,
                indicator_id,
                observable_value,
                observable_kind,
                source,
                reputation,
                risk_points,
                matched_at_utc,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                alert.event_id,
                alert.alert_id,
                indicator_id,
                str(metadata.get("observable_value") or ""),
                str(metadata.get("observable_kind") or ""),
                str(metadata.get("source") or ""),
                str(metadata.get("reputation") or ""),
                int_or_zero(metadata.get("risk_points")),
                dt_to_text(alert.created_at_utc),
                json.dumps(metadata, sort_keys=True),
            ),
        )

    def _direction(self, source: str, destination: str) -> str:
        if not destination or destination.startswith(("0.", "127.")):
            return "local"
        if source and source == destination:
            return "local"
        return "outbound"

    def _software_terms(self, event: SensorEvent) -> list[str]:
        terms = []
        for key in (
            "software",
            "product",
            "service",
            "service_name",
            "banner",
            "version",
            "image_name",
            "process_name",
        ):
            value = str(event.payload.get(key) or "").strip()
            if len(value) >= 3:
                terms.append(value)
        remote_port = int_or_zero(event.payload.get("remote_port"))
        port_services = {22: "ssh", 80: "http", 443: "https", 445: "smb", 3389: "rdp"}
        if remote_port in port_services:
            terms.append(port_services[remote_port])
        return sorted(set(terms), key=str.lower)

    def _table_exists(self, table: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
        return row is not None

    def _json(self, value: str | None) -> dict:
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def save_finding_mappings(self, finding: DetectionFinding, mapper: MitreMapper) -> None:
        for technique in mapper.map_finding(finding):
            self._conn.execute(
                """
                INSERT OR IGNORE INTO mitre_techniques (technique_id, name, tactic)
                VALUES (?, ?, ?)
                """,
                (technique.technique_id, technique.name, technique.tactic),
            )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO finding_mitre_techniques (finding_id, technique_id)
                VALUES (?, ?)
                """,
                (finding.finding_id, technique.technique_id),
            )
        self._conn.commit()

    def save_alert_mappings(self, alert: DetectionAlert, mapper: MitreMapper, finding: DetectionFinding) -> None:
        for technique in mapper.map_finding(finding):
            self._conn.execute(
                """
                INSERT OR IGNORE INTO mitre_techniques (technique_id, name, tactic)
                VALUES (?, ?, ?)
                """,
                (technique.technique_id, technique.name, technique.tactic),
            )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO mitre_mappings (
                    mapping_id,
                    alert_id,
                    finding_id,
                    technique_id,
                    tactic,
                    technique_name,
                    confidence,
                    source,
                    created_at_utc,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{alert.alert_id}:{technique.technique_id}",
                    alert.alert_id,
                    finding.finding_id,
                    technique.technique_id,
                    technique.tactic,
                    technique.name,
                    "medium",
                    "engine",
                    dt_to_text(alert.created_at_utc),
                    json.dumps({"provider_id": finding.provider_id}, sort_keys=True),
                ),
            )
        self._conn.commit()
