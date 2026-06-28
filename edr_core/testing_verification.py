from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from .db import execute, fetch_all, json_dumps, utc_now
from .detection import analyze_event
from .dns_monitor import DOH_ENDPOINTS
from .ingestion import ingest
from .live_presence import scan_presence
from .performance import record_system_metrics
from .sessions import get_current_session_id


@dataclass
class VerificationTest:
    name: str
    expected_malicious: bool
    events: list[dict[str, Any]]


def tests() -> list[VerificationTest]:
    return [
        VerificationTest("Phone connects to WiFi", False, [{"event_type": "device", "ip": "10.250.1.20", "mac": "02:11:22:33:44:55", "hostname": "phone", "device_type": "phone/tablet", "trust_status": "unknown", "source": "testing_verification"}]),
        VerificationTest("Phone disconnects from WiFi", False, []),
        VerificationTest("Safe browsing", False, [{"event_type": "dns", "source_ip": "10.250.1.10", "domain": "example.com", "source": "testing_verification"}]),
        VerificationTest("Suspicious domain visit", False, [{"event_type": "dns", "source_ip": "10.250.1.10", "domain": "a9f8e7d6c5b4a3f2e1d0c9b8a7.xyz", "source": "testing_verification"}]),
        VerificationTest("Malicious domain from local threat_intel list", True, [{"event_type": "dns", "source_ip": "10.250.1.10", "domain": "malware-test.example", "source": "testing_verification"}]),
        VerificationTest("Malicious IP connection", True, [{"event_type": "connection", "source_ip": "10.250.1.10", "destination_ip": "203.0.113.66", "port": 443, "protocol": "TCP", "source": "testing_verification"}]),
        VerificationTest("DNS over HTTPS detection", False, [{"event_type": "dns", "source_ip": "10.250.1.10", "domain": next(iter(DOH_ENDPOINTS)), "source": "testing_verification"}]),
        VerificationTest("3 failed login attempts", True, [{"event_type": "auth_log", "username": "admin", "source_ip": "10.250.1.30", "target_system": "vpn", "outcome": "failed", "log_source": "testing_verification"} for _ in range(3)]),
        VerificationTest("Port scan", True, [{"event_type": "connection", "source_ip": "10.250.1.40", "destination_ip": "10.250.1.50", "port": port, "protocol": "TCP", "process_name": "ncat.exe", "source": "testing_verification"} for port in range(20, 35)]),
        VerificationTest("Traffic spike", False, [{"event_type": "traffic", "source_ip": "10.250.1.60", "destination_ip": "198.51.100.90", "bytes_total": 80_000_000, "window_seconds": 60, "source": "testing_verification"}]),
    ]


def _outcome(expected: bool, detected: bool) -> str:
    if expected and detected:
        return "TP"
    if not expected and not detected:
        return "TN"
    if not expected and detected:
        return "FP"
    return "FN"


def run_testing_verification() -> dict[str, Any]:
    session_id = get_current_session_id()
    if not session_id:
        raise RuntimeError("Start Monitoring before running testing verification.")
    results = []
    for test in tests():
        start = time.perf_counter()
        alert_ids: list[int] = []
        evidence: list[dict[str, Any]] = []
        if test.name == "Phone disconnects from WiFi":
            evidence.append(scan_presence(offline_after_seconds=0))
        for raw in test.events:
            event = ingest(raw)
            ids = analyze_event(event)
            alert_ids.extend(ids)
            evidence.append(raw)
        high_signal = []
        for alert_id in alert_ids:
            rows = fetch_all("SELECT classification FROM alerts WHERE id = ?", (alert_id,))
            if rows and rows[0]["classification"] in {"SUSPICIOUS", "HIGH RISK", "CONFIRMED THREAT"}:
                high_signal.append(alert_id)
        detected = bool(high_signal)
        outcome = _outcome(test.expected_malicious, detected)
        pass_fail = "PASS" if outcome in {"TP", "TN"} else "FAIL"
        elapsed = (time.perf_counter() - start) * 1000
        execute(
            """
            INSERT INTO testing_verification(session_id, timestamp, test_name, expected_result,
                                             actual_result, pass_fail, outcome, detection_time_ms, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                utc_now(),
                test.name,
                "malicious" if test.expected_malicious else "safe/informational",
                "detected" if detected else "not_detected",
                pass_fail,
                outcome,
                elapsed,
                json_dumps({"alert_ids": high_signal, "evidence": evidence}),
            ),
        )
        results.append({"test": test.name, "outcome": outcome, "pass_fail": pass_fail, "detection_time_ms": elapsed})
    record_system_metrics("testing_verification")
    totals = {key: sum(1 for item in results if item["outcome"] == key) for key in ["TP", "TN", "FP", "FN"]}
    total = len(results)
    accuracy = (totals["TP"] + totals["TN"]) / total if total else 0
    fpr = totals["FP"] / (totals["FP"] + totals["TN"]) if (totals["FP"] + totals["TN"]) else 0
    fnr = totals["FN"] / (totals["FN"] + totals["TP"]) if (totals["FN"] + totals["TP"]) else 0
    return {"results": results, "totals": totals, "accuracy": accuracy, "false_positive_rate": fpr, "false_negative_rate": fnr}


def main() -> None:
    print(json.dumps(run_testing_verification(), indent=2))


if __name__ == "__main__":
    main()

