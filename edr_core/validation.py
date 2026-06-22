from __future__ import annotations

import time
import copy
from dataclasses import dataclass
from typing import Any

from .db import execute, fetch_all, init_db, json_dumps, utc_now
from .detection import analyze_event
from .ingestion import ingest
from .performance import record_system_metrics
from .threat_intel import seed_intel_db


@dataclass
class ValidationTest:
    name: str
    expected_malicious: bool
    events: list[dict[str, Any]]


def validation_tests() -> list[ValidationTest]:
    return [
        ValidationTest(
            "Trusted Device",
            False,
            [{"event_type": "device", "ip": "192.168.1.10", "mac": "00-11-22-33-44-55", "hostname": "admin-pc", "trust_status": "trusted"}],
        ),
        ValidationTest(
            "Phone Connected",
            False,
            [{"event_type": "device", "ip": "192.168.1.25", "mac": "10-20-30-40-50-60", "hostname": "phone", "device_type": "mobile", "trust_status": "unknown"}],
        ),
        ValidationTest(
            "Safe Browsing",
            False,
            [
                {"event_type": "dns", "source_ip": "192.168.1.10", "domain": "example.com", "resolved_ip": "93.184.216.34"},
                {"event_type": "connection", "source_ip": "192.168.1.10", "destination_ip": "93.184.216.34", "port": 443, "protocol": "TCP", "process_name": "chrome.exe"},
            ],
        ),
        ValidationTest(
            "Malicious IP",
            True,
            [{"event_type": "connection", "source_ip": "192.168.1.10", "destination_ip": "203.0.113.66", "port": 443, "protocol": "TCP", "process_name": "powershell.exe"}],
        ),
        ValidationTest(
            "Malicious Domain",
            True,
            [{"event_type": "dns", "source_ip": "192.168.1.10", "domain": "malware-test.example", "resolved_ip": "203.0.113.66"}],
        ),
        ValidationTest(
            "Beaconing",
            True,
            [
                {"event_type": "connection", "source_ip": "192.168.1.20", "destination_ip": "198.51.100.23", "port": 443, "protocol": "TCP", "process_name": "svchost.exe"}
                for _ in range(9)
            ],
        ),
        ValidationTest(
            "Port Scan",
            True,
            [
                {"event_type": "connection", "source_ip": "192.168.1.30", "destination_ip": "192.168.1.40", "port": port, "protocol": "TCP", "process_name": "ncat.exe"}
                for port in range(20, 35)
            ],
        ),
        ValidationTest(
            "Traffic Spike",
            True,
            [{"event_type": "traffic", "source_ip": "192.168.1.44", "destination_ip": "198.51.100.90", "bytes_total": 80_000_000, "window_seconds": 60}],
        ),
        ValidationTest(
            "Suspicious DNS",
            True,
            [{"event_type": "dns", "source_ip": "192.168.1.10", "domain": "a9f8e7d6c5b4a3f2e1d0c9b8a7.xyz"}],
        ),
        ValidationTest(
            "CVE Match",
            True,
            [{"event_type": "device", "ip": "192.168.1.88", "hostname": "legacy-web", "software": [{"name": "Apache httpd", "version": "2.4.49"}], "trust_status": "trusted"}],
        ),
        ValidationTest(
            "Malicious Hash",
            True,
            [
                {
                    "event_type": "file_scan",
                    "file_path": "C:\\Users\\PC\\Downloads\\invoice.exe",
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "signed": False,
                    "source": "validation",
                }
            ],
        ),
        ValidationTest(
            "Suspicious Startup File",
            True,
            [
                {
                    "event_type": "file_scan",
                    "file_path": "C:\\Users\\PC\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.ps1",
                    "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "signed": False,
                    "source": "validation",
                }
            ],
        ),
        ValidationTest(
            "Suspicious PowerShell",
            True,
            [
                {
                    "event_type": "process_scan",
                    "process_name": "powershell.exe",
                    "pid": 4242,
                    "command_line": "powershell.exe -ExecutionPolicy Bypass -enc AAAA",
                    "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "source": "validation",
                }
            ],
        ),
        ValidationTest(
            "Three Failed Login Attempts",
            True,
            [
                {"event_type": "auth_log", "username": "admin", "source_ip": "192.168.3.50", "target_system": "vpn", "outcome": "failed", "log_source": "validation"}
                for _ in range(3)
            ],
        ),
        ValidationTest(
            "Success After Failures",
            True,
            [
                *[
                    {"event_type": "auth_log", "username": "dbuser", "source_ip": "192.168.3.60", "target_system": "database", "outcome": "failed", "log_source": "validation"}
                    for _ in range(3)
                ],
                {"event_type": "auth_log", "username": "dbuser", "source_ip": "192.168.3.60", "target_system": "database", "outcome": "success", "log_source": "validation"},
            ],
        ),
        ValidationTest(
            "Database Access Attempt",
            True,
            [{"event_type": "database_log", "username": "unknown", "source_ip": "192.168.3.70", "target_system": "database", "outcome": "failed", "log_source": "validation"}],
        ),
        ValidationTest(
            "Normal Local File Transfer",
            False,
            [{"event_type": "file_scan", "file_path": "C:\\Users\\PC\\Documents\\report.pdf", "sha256": "", "signed": None, "source": "validation"}],
        ),
        ValidationTest(
            "Normal Gmail Traffic",
            False,
            [
                {"event_type": "dns", "source_ip": "192.168.3.20", "domain": "mail.google.com", "resolved_ip": "142.250.191.37"},
                {"event_type": "connection", "source_ip": "192.168.3.20", "destination_ip": "142.250.191.37", "port": 443, "protocol": "TCP", "process_name": "chrome.exe"},
            ],
        ),
    ]


def _outcome(expected: bool, detected: bool) -> str:
    if expected and detected:
        return "TP"
    if not expected and not detected:
        return "TN"
    if not expected and detected:
        return "FP"
    return "FN"


def _scope_events(events: list[dict[str, Any]], bucket: int) -> list[dict[str, Any]]:
    scoped = copy.deepcopy(events)

    def scope_value(value: Any) -> Any:
        if isinstance(value, str):
            value = value.replace("192.168.1.", f"10.240.{bucket}.")
            value = value.replace("192.168.3.", f"10.241.{bucket}.")
        elif isinstance(value, list):
            value = [scope_value(item) for item in value]
        elif isinstance(value, dict):
            value = {key: scope_value(item) for key, item in value.items()}
        return value

    return [scope_value(event) for event in scoped]


def run_validation() -> dict[str, Any]:
    init_db()
    seed_intel_db()
    results = []
    bucket = int(time.time()) % 200 + 1
    validation_run_id = f"validation-{int(time.time())}"
    for test in validation_tests():
        start = time.perf_counter()
        alert_ids: list[int] = []
        for raw in _scope_events(test.events, bucket):
            event = ingest(raw)
            ids = analyze_event(event)
            high_signal_ids = []
            for alert_id in ids:
                row = fetch_all("SELECT score FROM alerts WHERE id = ?", (alert_id,))
                if row and int(row[0]["score"]) > 10:
                    high_signal_ids.append(alert_id)
            alert_ids.extend(high_signal_ids)
        response_ms = (time.perf_counter() - start) * 1000
        detected = bool(alert_ids)
        outcome = _outcome(test.expected_malicious, detected)
        notes = "Unknown-device-only informational alerts are excluded from malicious verdicts."
        execute(
            """
            INSERT INTO validation_results(timestamp, test_name, expected_malicious, detected_malicious,
                                           outcome, response_ms, alert_ids, notes, validation_run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (utc_now(), test.name, int(test.expected_malicious), int(detected), outcome, response_ms, json_dumps(alert_ids), notes, validation_run_id),
        )
        results.append({"test": test.name, "expected_malicious": test.expected_malicious, "detected": detected, "outcome": outcome, "response_ms": response_ms})

    totals = {key: sum(1 for item in results if item["outcome"] == key) for key in ["TP", "TN", "FP", "FN"]}
    total = len(results)
    accuracy = (totals["TP"] + totals["TN"]) / total if total else 0.0
    false_positive_rate = totals["FP"] / (totals["FP"] + totals["TN"]) if (totals["FP"] + totals["TN"]) else 0.0
    false_negative_rate = totals["FN"] / (totals["FN"] + totals["TP"]) if (totals["FN"] + totals["TP"]) else 0.0
    record_system_metrics("validation")
    return {
        "results": results,
        "totals": totals,
        "accuracy": accuracy,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "average_response_ms": sum(item["response_ms"] for item in results) / total if total else 0.0,
        "validation_run_id": validation_run_id,
    }


def main() -> None:
    summary = run_validation()
    print("Validation complete")
    print(f"Accuracy: {summary['accuracy']:.2%}")
    print(f"FPR: {summary['false_positive_rate']:.2%}")
    print(f"FNR: {summary['false_negative_rate']:.2%}")
    print(f"Totals: {summary['totals']}")


if __name__ == "__main__":
    main()
