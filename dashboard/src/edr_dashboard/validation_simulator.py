from __future__ import annotations

import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import psutil

from edr_dashboard.device_discovery import DEFAULT_DB_PATH, PROJECT_ROOT


DETECTION_ENGINE_SRC = PROJECT_ROOT / "detection_engine" / "src"
if str(DETECTION_ENGINE_SRC) not in sys.path:
    sys.path.insert(0, str(DETECTION_ENGINE_SRC))

from edr_engine.app import build_engine  # noqa: E402
from edr_engine.core.events import SensorEvent  # noqa: E402


@dataclass(frozen=True)
class ValidationScenario:
    key: str
    name: str
    expected_result: str
    expected_categories: set[str]
    events: list[SensorEvent]
    expected_positive: bool = True


class CybersecurityValidationSimulator:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.migrations_dir = PROJECT_ROOT / "database" / "migrations"

    def run_test(self, test_key: str) -> dict:
        scenario = self._scenario(test_key)
        engine, store = build_engine(self.db_path, self.migrations_dir)
        process = psutil.Process()
        cpu_before = psutil.cpu_percent(interval=None)
        memory_before = process.memory_info().rss
        started = time.perf_counter()
        try:
            for event in scenario.events:
                engine.ingest(event)
        finally:
            store.close()
        response_time_ms = int((time.perf_counter() - started) * 1000)
        cpu_after = psutil.cpu_percent(interval=None)
        memory_after = process.memory_info().rss

        alerts = self._alerts_for_events([event.event_id for event in scenario.events])
        categories = {str(alert.get("category", "")) for alert in alerts}
        matched = sorted(scenario.expected_categories & categories)
        detected_positive = self._detected_positive(alerts)
        expected_positive = scenario.expected_positive
        passed = (expected_positive and bool(matched)) or (not expected_positive and not detected_positive)
        true_positive = int(expected_positive and detected_positive and bool(matched))
        true_negative = int(not expected_positive and not detected_positive)
        false_positive = int(not expected_positive and detected_positive)
        false_negative = int(expected_positive and not bool(matched))
        evidence = self._evidence(alerts, matched)
        return {
            "test": scenario.name,
            "expected_result": scenario.expected_result,
            "actual_result": self._actual_result(alerts, matched, expected_positive, detected_positive),
            "pass_fail": "PASS" if passed else "FAIL",
            "evidence": evidence,
            "expected_positive": expected_positive,
            "detected_positive": detected_positive,
            "true_positive": true_positive,
            "true_negative": true_negative,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "response_time_ms": response_time_ms,
            "cpu_usage_percent": max(cpu_before, cpu_after),
            "memory_usage_mb": round(max(memory_before, memory_after) / (1024 * 1024), 2),
            "ioc_matches": sum(1 for alert in alerts if str(alert.get("category", "")).startswith("threat_intel_") and alert.get("category") != "threat_intel_cve"),
            "cve_matches": sum(1 for alert in alerts if alert.get("category") == "threat_intel_cve"),
        }

    def _scenario(self, test_key: str) -> ValidationScenario:
        run_id = uuid4().hex[:8]
        asset_id = f"SIM-{test_key.upper()}-{run_id}"
        start = datetime.now(timezone.utc).replace(microsecond=0)

        if test_key == "unknown_device":
            return ValidationScenario(
                key=test_key,
                name="Unknown Device Test",
                expected_result="Generate informational unknown-device evidence without promoting the event to high risk.",
                expected_categories={"asset_inventory"},
                expected_positive=False,
                events=[
                    self._network_event(
                        "unknown",
                        asset_id,
                        start,
                        "203.0.113.20",
                        443,
                    )
                ],
            )

        if test_key == "safe_device":
            return ValidationScenario(
                key=test_key,
                name="Safe Device True Negative Test",
                expected_result="Do not classify a known safe event as suspicious or high risk.",
                expected_categories=set(),
                expected_positive=False,
                events=[
                    self._network_event(
                        "safe",
                        "TRUSTED-SAFE-DEVICE",
                        start,
                        "93.184.216.34",
                        443,
                    )
                ],
            )

        if test_key == "dns":
            return ValidationScenario(
                key=test_key,
                name="DNS Test",
                expected_result="Generate a Suspicious DNS alert for high-risk or algorithmic DNS telemetry.",
                expected_categories={"dns_tld_reputation", "possible_dga", "dns_length_anomaly"},
                events=[
                    SensorEvent(
                        schema_version="1.0",
                        event_id=f"sim-{run_id}-dns-001",
                        event_type="dns.query",
                        asset_id=asset_id,
                        timestamp_utc=start,
                        source="validation_simulator",
                        payload={"query": f"xj92ksla88qqw7z19pqq-{run_id}.example.xyz"},
                    )
                ],
            )

        if test_key == "beaconing":
            return ValidationScenario(
                key=test_key,
                name="Beaconing Test",
                expected_result="Generate a Beaconing alert for near-regular outbound connection intervals.",
                expected_categories={"beaconing"},
                events=[
                    self._network_event(
                        f"beacon-{index}",
                        asset_id,
                        start + timedelta(seconds=30 * index),
                        "203.0.113.30",
                        443,
                    )
                    for index in range(4)
                ],
            )

        if test_key == "repeated_connection":
            return ValidationScenario(
                key=test_key,
                name="Repeated Connection Test",
                expected_result="Generate a Repeated Connection alert after repeated outbound connections to the same endpoint.",
                expected_categories={"repeated_connection"},
                events=[
                    self._network_event(
                        f"repeat-{index}",
                        asset_id,
                        start + timedelta(seconds=20 * index),
                        "203.0.113.40",
                        8443,
                    )
                    for index in range(5)
                ],
            )

        if test_key == "traffic_spike":
            return ValidationScenario(
                key=test_key,
                name="Traffic Spike Test",
                expected_result="Generate a Large Data Transfer alert when outbound bytes exceed the configured threshold.",
                expected_categories={"large_data_transfer"},
                events=[
                    self._network_event(
                        "spike",
                        asset_id,
                        start,
                        "203.0.113.50",
                        443,
                        {"bytes_sent": 75 * 1024 * 1024},
                    )
                ],
            )

        raise ValueError(f"Unknown validation test: {test_key}")

    def _network_event(
        self,
        suffix: str,
        asset_id: str,
        timestamp: datetime,
        remote_address: str,
        remote_port: int,
        extra_payload: dict | None = None,
    ) -> SensorEvent:
        payload = {
            "protocol": "tcp",
            "process_id": 9001,
            "local_address": "192.168.3.250",
            "local_port": 50000 + (remote_port % 1000),
            "remote_address": remote_address,
            "remote_port": remote_port,
            "state": "ESTABLISHED",
        }
        payload.update(extra_payload or {})
        return SensorEvent(
            schema_version="1.0",
            event_id=f"sim-{asset_id.lower()}-{suffix}",
            event_type="network.connection_observed",
            asset_id=asset_id,
            timestamp_utc=timestamp,
            source="validation_simulator",
            payload=payload,
        )

    def _alerts_for_events(self, event_ids: list[str]) -> list[dict]:
        placeholders = ",".join("?" for _ in event_ids)
        query = f"""
            SELECT alert_id, title, severity, risk_score, description, event_id, metadata_json
            FROM alerts
            WHERE event_id IN ({placeholders})
            ORDER BY created_at_utc
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, event_ids).fetchall()

        alerts = []
        for row in rows:
            metadata = self._metadata(row["metadata_json"])
            alerts.append(
                {
                    "alert_id": row["alert_id"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "risk_score": row["risk_score"],
                    "description": row["description"],
                    "event_id": row["event_id"],
                    "category": metadata.get("category", ""),
                }
            )
        return alerts

    def _metadata(self, value: str | None) -> dict:
        if not value:
            return {}
        import json

        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _actual_result(self, alerts: list[dict], matched: list[str], expected_positive: bool = True, detected_positive: bool = True) -> str:
        if not expected_positive and not detected_positive:
            return "No suspicious/high-risk detection generated for the safe scenario."
        if not expected_positive and detected_positive:
            return "False positive: safe scenario was classified as suspicious or higher."
        if not alerts:
            return "No alerts generated."
        if matched:
            return f"Generated expected alert category: {', '.join(matched)}."
        categories = sorted({str(alert.get("category", "")) for alert in alerts if alert.get("category")})
        return f"Generated alerts, but expected category was not found. Categories: {', '.join(categories) or 'none'}."

    def _detected_positive(self, alerts: list[dict]) -> bool:
        for alert in alerts:
            risk_score = int(alert.get("risk_score") or 0)
            category = str(alert.get("category", ""))
            if risk_score >= 31:
                return True
            if category.startswith("threat_intel_"):
                return True
        return False

    def _evidence(self, alerts: list[dict], matched: list[str]) -> str:
        if not alerts:
            return "No matching alert rows were written to SQLite."
        lines = []
        for alert in alerts:
            marker = "matched" if alert.get("category") in matched else "observed"
            lines.append(
                f"{marker}: {alert['title']} | severity={alert['severity']} | "
                f"risk={alert['risk_score']} | category={alert.get('category', '')} | alert={alert['alert_id']}"
            )
        return "; ".join(lines)
