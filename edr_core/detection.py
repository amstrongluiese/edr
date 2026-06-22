from __future__ import annotations

import json
import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .config import MITRE_MAP, RISKY_PORTS, SUSPICIOUS_PATH_MARKERS, SUSPICIOUS_TLDS
from .db import execute, fetch_all, fetch_one, json_dumps, record_metric, utc_now
from .models import AlertCandidate, NormalizedEvent
from .risk import risk_level
from .threat_intel import match_cves, match_iocs


SAFE_PROCESSES = {"chrome.exe", "msedge.exe", "firefox.exe", "svchost.exe", "system", "teams.exe"}
SUSPICIOUS_PROCESS_NAMES = {"mimikatz.exe", "procdump.exe", "psexec.exe", "powershell_ise.exe", "nc.exe", "ncat.exe"}
SUSPICIOUS_COMMAND_MARKERS = ["-enc", "downloadstring", "invoke-webrequest", "bypass", "hidden", "iex", "frombase64string"]


def _parse_ts(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _add_alert(candidate: AlertCandidate) -> int:
    tactic, technique, attack_id = MITRE_MAP.get(candidate.alert_type, ("Unmapped", "Unmapped", "N/A"))
    severity = risk_level(candidate.score)
    now = utc_now()
    evidence_json = json_dumps(candidate.evidence)
    evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    existing = fetch_one(
        """
        SELECT id, occurrence_count, score
        FROM alerts
        WHERE alert_type = ? AND entity = ? AND evidence_hash = ? AND status IN ('open', 'grouped')
        ORDER BY id DESC LIMIT 1
        """,
        (candidate.alert_type, candidate.entity, evidence_hash),
    )
    if existing:
        execute(
            """
            UPDATE alerts
            SET last_seen = ?,
                timestamp = ?,
                occurrence_count = occurrence_count + 1,
                score = MAX(score, ?),
                severity = ?,
                status = 'grouped'
            WHERE id = ?
            """,
            (now, now, candidate.score, risk_level(max(int(existing["score"]), candidate.score)), existing["id"]),
        )
        _update_device_risk(candidate)
        return int(existing["id"])
    alert_id = execute(
        """
        INSERT INTO alerts(timestamp, first_seen, last_seen, alert_type, entity, severity, score, evidence,
                           evidence_hash, reason, mitre_tactic, mitre_technique, mitre_id, occurrence_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (
            now,
            now,
            now,
            candidate.alert_type,
            candidate.entity,
            severity,
            candidate.score,
            evidence_json,
            evidence_hash,
            candidate.reason,
            tactic,
            technique,
            attack_id,
        ),
    )
    _update_device_risk(candidate)
    return alert_id


def _update_device_risk(candidate: AlertCandidate) -> None:
    candidate_ips = set()
    for key in ("ip", "source_ip", "destination_ip", "resolved_ip"):
        value = candidate.evidence.get(key)
        if isinstance(value, str) and value.count(".") == 3:
            candidate_ips.add(value)
    if candidate.entity.count(".") == 3:
        candidate_ips.add(candidate.entity)

    # Unknown-device-only evidence remains informational by design.
    score = min(100, max(0, int(candidate.score)))
    level = risk_level(score)
    for ip in candidate_ips:
        execute(
            """
            UPDATE devices
            SET risk_score = MAX(risk_score, ?),
                risk_level = ?,
                last_seen = ?,
                online_status = 'online'
            WHERE ip = ? AND risk_score <= ?
            """,
            (score, level, utc_now(), ip, score),
        )


def _connection_stats(source_ip: str | None, destination_ip: str | None) -> dict[str, Any]:
    rows = fetch_all(
        """
        SELECT timestamp, destination_ip, port
        FROM connections
        WHERE (? IS NULL AND source_ip IS NULL) OR source_ip = ?
        ORDER BY id DESC LIMIT 80
        """,
        (source_ip, source_ip),
    )
    same_dest = [row for row in rows if destination_ip and row["destination_ip"] == destination_ip]
    ports = {int(row["port"]) for row in rows if row["port"] is not None}
    return {"recent_count": len(rows), "same_destination_count": len(same_dest), "unique_ports": len(ports)}


def detect_candidates(event: NormalizedEvent) -> list[AlertCandidate]:
    candidates: list[AlertCandidate] = []

    if event.event_type in {"device", "device_seen"} and event.ip:
        existing = fetch_one("SELECT trust_status FROM devices WHERE ip = ?", (event.ip,))
        if event.trust_status == "unknown" or (existing and existing["trust_status"] == "unknown"):
            candidates.append(
                AlertCandidate(
                    "unknown_device",
                    event.ip,
                    5,
                    {"ip": event.ip, "mac": event.mac, "hostname": event.hostname, "discovery_source": event.discovery_source},
                    "Device is visible but unclassified. Unknown device alone is informational and not treated as a threat.",
                )
            )
        for port in event.open_ports:
            if int(port) in RISKY_PORTS:
                candidates.append(
                    AlertCandidate(
                        "risky_open_port",
                        event.ip,
                        15,
                        {"ip": event.ip, "open_port": int(port)},
                        f"Device exposes risky administrative or legacy port {port}.",
                    )
                )

    if event.event_type in {"dns", "dns_query"} and event.domain:
        domain = event.domain.lower()
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) or len(domain.split(".")[0]) > 24:
            candidates.append(
                AlertCandidate(
                    "suspicious_dns",
                    domain,
                    25,
                    {"domain": domain, "source_ip": event.source_ip},
                    "Domain shape or TLD is suspicious compared with normal browsing patterns.",
                )
            )
        for match in match_iocs(domain=domain, ip=event.resolved_ip):
            score = 40 if match["type"] in {"malicious_ip", "malicious_domain"} else 30
            candidates.append(
                    AlertCandidate(
                        match["type"],
                        match["indicator"],
                        score,
                        {"match": match, "domain": domain, "source_ip": event.source_ip, "resolved_ip": event.resolved_ip},
                        f"Indicator matched threat intelligence source {match['source']}.",
                    )
                )

    if event.event_type in {"connection", "network", "process_connection"}:
        stats = _connection_stats(event.source_ip, event.destination_ip)
        if event.destination_ip:
            for match in match_iocs(ip=event.destination_ip, file_hash=event.file_hash):
                score = 50 if match["type"] == "malicious_hash" else 40
                candidates.append(
                    AlertCandidate(
                        match["type"],
                        match["indicator"],
                        score,
                        {
                            "match": match,
                            "source_ip": event.source_ip,
                            "destination_ip": event.destination_ip,
                            "process": event.process_name,
                            "pid": event.pid,
                        },
                        f"Connection or process artifact matched threat intelligence source {match['source']}.",
                    )
                )
        if event.port in RISKY_PORTS:
            candidates.append(
                AlertCandidate(
                    "risky_open_port",
                    event.destination_ip or event.source_ip or "unknown",
                    15,
                    {"destination_ip": event.destination_ip, "port": event.port, "process": event.process_name},
                    f"Connection targets risky port {event.port}.",
                )
            )
        if stats["same_destination_count"] >= 8:
            candidates.append(
                AlertCandidate(
                    "beaconing",
                    event.destination_ip or "unknown",
                    30,
                    {"same_destination_count": stats["same_destination_count"], "source_ip": event.source_ip},
                    "Repeated connections to the same destination indicate possible beaconing.",
                )
            )
        if stats["recent_count"] >= 20:
            candidates.append(
                AlertCandidate(
                    "repeated_connections",
                    event.source_ip or "unknown",
                    20,
                    {"recent_connection_count": stats["recent_count"], "source_ip": event.source_ip},
                    "High repeated connection volume observed in the recent telemetry window.",
                )
            )
        if stats["unique_ports"] >= 12:
            candidates.append(
                AlertCandidate(
                    "port_scan",
                    event.source_ip or "unknown",
                    30,
                    {"unique_ports": stats["unique_ports"], "source_ip": event.source_ip},
                    "Many unique destination ports were contacted, consistent with scanning.",
                )
            )
        process = (event.process_name or "").lower()
        if process in SUSPICIOUS_PROCESS_NAMES or (process.startswith("powershell") and event.destination_ip):
            candidates.append(
                AlertCandidate(
                    "suspicious_process",
                    event.process_name or "unknown",
                    25,
                    {
                        "process_name": event.process_name,
                        "pid": event.pid,
                        "source_ip": event.source_ip,
                        "destination_ip": event.destination_ip,
                    },
                    "Process name and network behavior match a suspicious administrative or dual-use pattern.",
                )
            )

    if event.event_type in {"traffic", "traffic_window"} and event.bytes_total > 50_000_000:
        candidates.append(
            AlertCandidate(
                "traffic_spike",
                event.source_ip or event.destination_ip or "unknown",
                20,
                {"bytes_total": event.bytes_total, "window_seconds": event.window_seconds},
                "Traffic volume exceeded the configured baseline threshold.",
            )
        )

    if event.event_type in {"file", "file_event", "file_scan"} and event.file_path:
        path_lower = event.file_path.lower()
        for match in match_iocs(file_hash=event.file_hash, url=event.url):
            score = 50 if match["type"] == "malicious_hash" else 40
            candidates.append(
                AlertCandidate(
                    match["type"],
                    match["indicator"],
                    score,
                    {"match": match, "file_path": event.file_path, "sha256": event.file_hash},
                    f"File artifact matched threat intelligence source {match['source']}.",
                )
            )
        if any(marker in path_lower for marker in SUSPICIOUS_PATH_MARKERS):
            candidates.append(
                AlertCandidate(
                    "suspicious_file_path",
                    event.file_path,
                    15,
                    {"file_path": event.file_path, "sha256": event.file_hash, "data_source": event.log_source or event.event_type},
                    "Executable or script was observed in a user-writable suspicious location.",
                )
            )
        if "\\startup\\" in path_lower:
            candidates.append(
                AlertCandidate(
                    "startup_persistence",
                    event.file_path,
                    15,
                    {"file_path": event.file_path, "sha256": event.file_hash},
                    "File is present in a Startup folder and may run automatically.",
                )
            )
        if event.signed is False and path_lower.endswith((".exe", ".dll", ".msi", ".scr")):
            candidates.append(
                AlertCandidate(
                    "unsigned_executable",
                    event.file_path,
                    15,
                    {"file_path": event.file_path, "sha256": event.file_hash, "signed": event.signed},
                    "Executable file is unsigned or signature status could not be verified.",
                )
            )

    if event.event_type in {"process", "process_event", "process_scan"}:
        process = (event.process_name or "").lower()
        command = (event.command_line or "").lower()
        path_lower = (event.file_path or "").lower()
        if process in SUSPICIOUS_PROCESS_NAMES or any(marker in command for marker in SUSPICIOUS_COMMAND_MARKERS):
            candidates.append(
                AlertCandidate(
                    "suspicious_process",
                    event.process_name or event.file_path or "unknown_process",
                    25,
                    {
                        "process_name": event.process_name,
                        "pid": event.pid,
                        "parent_process": event.parent_process,
                        "command_line": event.command_line,
                        "executable_path": event.file_path,
                    },
                    "Process command line or name matches suspicious administrative or script execution behavior.",
                )
            )
        if any(marker in path_lower for marker in SUSPICIOUS_PATH_MARKERS):
            candidates.append(
                AlertCandidate(
                    "suspicious_file_path",
                    event.file_path or event.process_name or "unknown_process",
                    15,
                    {"process_name": event.process_name, "pid": event.pid, "executable_path": event.file_path},
                    "Process executable path is in a user-writable suspicious location.",
                )
            )
        for match in match_iocs(file_hash=event.file_hash):
            candidates.append(
                AlertCandidate(
                    match["type"],
                    match["indicator"],
                    50,
                    {"match": match, "process_name": event.process_name, "pid": event.pid, "sha256": event.file_hash},
                    f"Process hash matched threat intelligence source {match['source']}.",
                )
            )

    if event.event_type in {"auth_log", "access_log", "database_log", "server_log", "application_log"}:
        if event.event_type == "database_log" or "database" in (event.target_system or "").lower():
            candidates.append(
                AlertCandidate(
                    "database_access_attempt",
                    event.source_ip or event.username or "unknown_source",
                    30,
                    {
                        "username": event.username,
                        "source_ip": event.source_ip,
                        "device": event.hostname,
                        "target_system": event.target_system,
                        "outcome": event.outcome,
                        "data_source": event.log_source,
                    },
                    "Database or protected repository access was observed in imported logs.",
                )
            )
        candidates.extend(_failed_attempt_candidates(event))

    for cve in match_cves(event.software):
        evidence = {**cve, "ip": event.ip, "hostname": event.hostname}
        cvss = float(cve["cvss"])
        cve_severity = "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"
        execute(
            """
            INSERT INTO cve_matches(timestamp, product, version, cve_id, cvss, severity, description, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                cve["software"],
                cve["version"],
                cve["cve"],
                cvss,
                cve_severity,
                cve["summary"],
                "local_nvd_style_cache",
            ),
        )
        candidates.append(
            AlertCandidate(
                "critical_cve",
                cve["software"],
                50 if cvss >= 9 else 30,
                evidence,
                f"{cve['software']} {cve['version']} maps to {cve['cve']} with CVSS {cve['cvss']}.",
            )
        )

    return candidates


def _failed_attempt_candidates(event: NormalizedEvent) -> list[AlertCandidate]:
    if not event.outcome:
        return []
    outcome = event.outcome.lower()
    if outcome not in {"failed", "failure", "success", "successful"}:
        return []
    source_clause = """
        ((username IS NOT NULL AND username = ?) OR (source_ip IS NOT NULL AND source_ip = ?) OR (device IS NOT NULL AND device = ?))
    """
    rows = fetch_all(
        f"""
        SELECT id, timestamp, username, source_ip, device, target_system, outcome, raw_event
        FROM log_events
        WHERE {source_clause}
        ORDER BY id DESC LIMIT 20
        """,
        (event.username, event.source_ip, event.hostname),
    )
    failed_rows = [row for row in rows if str(row["outcome"]).lower() in {"failed", "failure"}]
    candidates: list[AlertCandidate] = []
    if len(failed_rows) >= 3 and outcome in {"failed", "failure"}:
        evidence_logs = [int(row["id"]) for row in failed_rows[:3]]
        execute(
            """
            INSERT INTO failed_attempts(timestamp, username, source_ip, device, target_system,
                                        failed_count, window_seconds, evidence_logs)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                event.username,
                event.source_ip,
                event.hostname,
                event.target_system,
                len(failed_rows),
                300,
                json.dumps(evidence_logs),
            ),
        )
        candidates.append(
            AlertCandidate(
                "failed_attempts",
                event.source_ip or event.username or "unknown_source",
                30,
                {
                    "username": event.username,
                    "source_ip": event.source_ip,
                    "device": event.hostname,
                    "target_system": event.target_system,
                    "failed_count": len(failed_rows),
                    "time_window_seconds": 300,
                    "evidence_logs": evidence_logs,
                    "data_source": event.log_source,
                },
                "Three or more failed attempts were observed for the same user, IP, or device.",
            )
        )
    if outcome in {"success", "successful"} and len(failed_rows) >= 3:
        candidates.append(
            AlertCandidate(
                "successful_login_after_failures",
                event.source_ip or event.username or "unknown_source",
                40,
                {
                    "username": event.username,
                    "source_ip": event.source_ip,
                    "device": event.hostname,
                    "target_system": event.target_system,
                    "previous_failed_count": len(failed_rows),
                    "data_source": event.log_source,
                },
                "Successful login occurred after repeated failures, indicating possible credential compromise.",
            )
        )
    return candidates


def correlate_incidents() -> None:
    open_alerts = fetch_all("SELECT * FROM alerts WHERE status = 'open' ORDER BY id DESC LIMIT 100")
    grouped: dict[str, list[Any]] = defaultdict(list)
    for alert in open_alerts:
        grouped[alert["entity"]].append(alert)
    for entity, rows in grouped.items():
        types = {row["alert_type"] for row in rows}
        if len(rows) < 2:
            continue
        if not ({"beaconing", "suspicious_dns", "malicious_ip", "malicious_domain", "port_scan", "failed_attempts", "database_access_attempt"} & types):
            continue
        score = min(100, sum(int(row["score"]) for row in rows))
        severity = risk_level(score)
        alert_ids = [int(row["id"]) for row in rows]
        title = f"{severity} incident involving {entity}"
        evidence = {
            "entity": entity,
            "alert_types": sorted(types),
            "alert_count": len(rows),
            "reason": "Related alerts share an entity and include high-signal threat behavior.",
        }
        execute(
            """
            INSERT INTO incidents(created_at, updated_at, title, severity, score, alert_ids, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (utc_now(), utc_now(), title, severity, score, json.dumps(alert_ids), json_dumps(evidence)),
        )
        for alert_id in alert_ids:
            execute("UPDATE alerts SET status = 'correlated' WHERE id = ?", (alert_id,))


def analyze_event(event: NormalizedEvent) -> list[int]:
    start = time.perf_counter()
    alert_ids = [_add_alert(candidate) for candidate in detect_candidates(event)]
    correlate_incidents()
    record_metric("detection_time", (time.perf_counter() - start) * 1000, "ms", {"event_type": event.event_type})
    return alert_ids


def summarize_counts() -> dict[str, int]:
    summary = {}
    for table in [
        "devices",
        "connections",
        "dns_logs",
        "alerts",
        "incidents",
        "validation_results",
        "scan_results",
        "file_events",
        "process_events",
        "log_events",
        "failed_attempts",
        "cve_matches",
    ]:
        row = fetch_one(f"SELECT COUNT(*) AS count FROM {table}")
        summary[table] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE is_inventory_device = 1")
    summary["unique_devices"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE is_inventory_device = 1 AND online_status = 'online'")
    summary["online_devices"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE is_inventory_device = 1 AND online_status != 'online'")
    summary["offline_devices"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE is_inventory_device = 1 AND trust_status = 'unknown'")
    summary["unknown_devices"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM (SELECT alert_type, entity FROM alerts GROUP BY alert_type, entity)")
    summary["grouped_alerts"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COALESCE(MAX(risk_score), 0) AS score FROM devices WHERE is_inventory_device = 1")
    summary["risk_score"] = int(row["score"] if row else 0)
    return summary
