from __future__ import annotations

import json
import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .config import DOH_DOMAINS, MITRE_MAP, RISKY_PORTS, SUSPICIOUS_PATH_MARKERS, SUSPICIOUS_TLDS
from .db import execute, fetch_all, fetch_one, json_dumps, record_metric, utc_now
from .models import AlertCandidate, NormalizedEvent
from .risk import confidence_label, evidence_classification, risk_level
from .sessions import get_current_session_id
from .threat_intel import match_cves, match_iocs, match_port_cves
from .accuracy_rules import domain_is_safe, ip_is_safe, match_sigma, match_yara_like, process_is_safe, vendor_is_safe


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
    session_id = get_current_session_id()
    historical = fetch_one(
        "SELECT COALESCE(SUM(occurrence_count), 0) AS count FROM alerts WHERE alert_type = ? AND entity = ?",
        (candidate.alert_type, candidate.entity),
    )
    history_count = int(historical["count"] if historical else 0)
    is_intel = candidate.alert_type.startswith("malicious_")
    is_cve = candidate.alert_type == "critical_cve"
    evidence_types = list(dict.fromkeys(candidate.evidence.get("supporting_evidence", [candidate.alert_type])))
    evidence_count = len(evidence_types)
    intel_confidence = int(candidate.evidence.get("match", {}).get("confidence", 0) or 0)
    cve_confidence = round(float(candidate.evidence.get("cvss", 0) or 0) * 10)
    confidence_score = min(
        100,
        max(
            intel_confidence,
            cve_confidence,
            max(0, int(candidate.score))
            + (20 if is_intel else 0)
            + (15 if is_cve else 0)
            + (0 if candidate.alert_type in {"unknown_device", "new_device", "repeated_connections", "possible_doh"} else 5 if attack_id != "N/A" else 0)
            + (30 if evidence_count >= 2 else 0)
            + min(15, history_count * 3),
        ),
    )
    classification = evidence_classification(
        candidate.alert_type,
        evidence_types,
        has_ioc=is_intel,
        has_cve=is_cve,
        validation_confirmed=bool(candidate.evidence.get("validation_confirmed")),
    )
    enriched_evidence = {
        **candidate.evidence,
        "score_breakdown": {candidate.alert_type: candidate.score},
        "data_source": candidate.evidence.get("data_source") or candidate.evidence.get("source") or candidate.evidence.get("discovery_source") or "telemetry",
        "classification": classification,
        "confidence_score": confidence_score,
        "confidence_label": confidence_label(confidence_score),
        "evidence_count": evidence_count,
        "evidence_list": evidence_types,
        "explanation": candidate.reason,
        "evidence_fusion": {
            "behavior_analysis": candidate.alert_type,
            "threat_intelligence": is_intel,
            "cve_correlation": is_cve,
            "mitre_mapping": attack_id,
            "historical_occurrences": history_count,
        },
    }
    evidence_json = json_dumps(enriched_evidence)
    stable_evidence = json_dumps({"alert_type": candidate.alert_type, "entity": candidate.entity, "evidence": candidate.evidence})
    evidence_hash = hashlib.sha256(stable_evidence.encode("utf-8")).hexdigest()
    existing = fetch_one(
        """
        SELECT id, occurrence_count, score
        FROM alerts
        WHERE alert_type = ? AND entity = ? AND evidence_hash = ? AND status IN ('open', 'grouped')
          AND ((? IS NULL AND session_id IS NULL) OR session_id = ?)
        ORDER BY id DESC LIMIT 1
        """,
        (candidate.alert_type, candidate.entity, evidence_hash, session_id, session_id),
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
                classification = ?,
                confidence_score = MAX(confidence_score, ?),
                confidence_label = ?,
                evidence_count = MAX(evidence_count, ?),
                status = 'grouped'
            WHERE id = ?
            """,
            (
                now,
                now,
                candidate.score,
                risk_level(max(int(existing["score"]), candidate.score)),
                classification,
                confidence_score,
                confidence_label(confidence_score),
                evidence_count,
                existing["id"],
            ),
        )
        _update_device_risk(candidate)
        return int(existing["id"])
    alert_id = execute(
        """
        INSERT INTO alerts(timestamp, first_seen, last_seen, alert_type, entity, severity, score,
                           classification, confidence_score, confidence_label, evidence_count, evidence,
                           evidence_hash, reason, mitre_tactic, mitre_technique, mitre_id, occurrence_count, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            now,
            now,
            now,
            candidate.alert_type,
            candidate.entity,
            severity,
            candidate.score,
            classification,
            confidence_score,
            confidence_label(confidence_score),
            evidence_count,
            evidence_json,
            evidence_hash,
            candidate.reason,
            tactic,
            technique,
            attack_id,
            session_id,
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
        if (event.trust_status == "unknown" or (existing and existing["trust_status"] == "unknown")) and not vendor_is_safe(event.vendor):
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
        safe_domain = domain_is_safe(domain)
        if not safe_domain and (any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) or len(domain.split(".")[0]) > 24):
            candidates.append(
                AlertCandidate(
                    "suspicious_dns",
                    domain,
                    25,
                    {"domain": domain, "source_ip": event.source_ip},
                    "Domain shape or TLD is suspicious compared with normal browsing patterns.",
                )
            )
        if domain in DOH_DOMAINS or any(domain.endswith("." + item) for item in DOH_DOMAINS):
            candidates.append(
                AlertCandidate(
                    "possible_doh",
                    domain,
                    20,
                    {"domain": domain, "source_ip": event.source_ip, "data_source": event.log_source or event.event_type},
                    "Endpoint contacted a known DNS-over-HTTPS provider; normal DNS query visibility may be reduced.",
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
        safe_connection = ip_is_safe(event.source_ip) or ip_is_safe(event.destination_ip) or process_is_safe(event.process_name)
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
        for cve in match_port_cves(event.port):
            cvss = float(cve["cvss"])
            candidates.append(
                AlertCandidate(
                    "critical_cve",
                    cve["software"],
                    50 if cvss >= 9 else 30,
                    {
                        **cve,
                        "source_ip": event.source_ip,
                        "destination_ip": event.destination_ip,
                        "port": event.port,
                        "data_source": event.log_source or event.event_type,
                    },
                    f"Open or active port {event.port} maps to {cve['cve']} exposure guidance with CVSS {cve['cvss']}.",
                )
            )
        if stats["same_destination_count"] >= 8 and not safe_connection:
            candidates.append(
                AlertCandidate(
                    "beaconing",
                    event.destination_ip or "unknown",
                    30,
                    {"same_destination_count": stats["same_destination_count"], "source_ip": event.source_ip},
                    "Repeated connections to the same destination indicate possible beaconing.",
                )
            )
        if stats["recent_count"] >= 20 and not safe_connection:
            candidates.append(
                AlertCandidate(
                    "repeated_connections",
                    event.source_ip or "unknown",
                    20,
                    {"recent_connection_count": stats["recent_count"], "source_ip": event.source_ip},
                    "High repeated connection volume observed in the recent telemetry window.",
                )
            )
        if stats["unique_ports"] >= 12 and not safe_connection:
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
        if process in SUSPICIOUS_PROCESS_NAMES or (process.startswith("powershell") and event.destination_ip and not process_is_safe(process)):
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

    for match in match_sigma(event):
        candidates.append(
            AlertCandidate(
                "sigma_rule",
                event.process_name or event.username or event.source_ip or "local-endpoint",
                int(match.get("score", 35)),
                {"sigma": match, "process_name": event.process_name, "command_line": event.command_line},
                f"Offline Sigma rule matched: {match.get('title', match.get('id', 'Sigma rule'))}.",
            )
        )
    for match in match_yara_like(event):
        candidates.append(
            AlertCandidate(
                "yara_rule",
                event.file_path or event.process_name or "local-artifact",
                int(match.get("score", 35)),
                {"yara": match, "file_path": event.file_path, "command_line": event.command_line},
                f"Offline YARA-compatible rule matched: {match['rule']}.",
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
            INSERT INTO cve_matches(timestamp, product, version, cve_id, cvss, severity, description, source, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                get_current_session_id(),
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
                                        failed_count, window_seconds, evidence_logs, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                get_current_session_id(),
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
    session_id = get_current_session_id()
    open_alerts = fetch_all(
        "SELECT * FROM alerts WHERE status = 'open' AND ((? IS NULL AND session_id IS NULL) OR session_id = ?) ORDER BY id DESC LIMIT 100",
        (session_id, session_id),
    )
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
            INSERT INTO incidents(created_at, updated_at, title, severity, score, alert_ids, evidence, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (utc_now(), utc_now(), title, severity, score, json.dumps(alert_ids), json_dumps(evidence), session_id),
        )
        for alert_id in alert_ids:
            execute("UPDATE alerts SET status = 'correlated' WHERE id = ?", (alert_id,))


def analyze_event(event: NormalizedEvent) -> list[int]:
    start = time.perf_counter()
    candidates = detect_candidates(event)
    for candidate in candidates:
        supporting = list(dict.fromkeys(item.alert_type for item in candidates))
        if candidate.alert_type == "failed_attempts":
            supporting.extend(f"failed_login_{index + 1}" for index in range(min(3, int(candidate.evidence.get("failed_count", 0)))))
        if candidate.alert_type == "beaconing":
            supporting.extend(["connection_repetition", "timing_pattern"])
        if candidate.alert_type == "port_scan":
            supporting.extend(["multi_port_contact", "scan_pattern"])
        if candidate.alert_type == "sigma_rule":
            supporting.extend(["sigma_rule", "sigma_process_context"])
        if candidate.alert_type == "yara_rule":
            supporting.extend(["yara_rule", "content_pattern"])
        candidate.evidence["supporting_evidence"] = list(dict.fromkeys(supporting))
    alert_ids = [_add_alert(candidate) for candidate in candidates]
    correlate_incidents()
    record_metric("detection_time", (time.perf_counter() - start) * 1000, "ms", {"event_type": event.event_type})
    return alert_ids


def summarize_counts(session_id: str | None = None) -> dict[str, int]:
    if session_id is None:
        from .sessions import get_current_session_id

        session_id = get_current_session_id()
    where = "WHERE session_id = ?"
    params = (session_id,)
    if not session_id:
        return {
            "devices": 0,
            "connections": 0,
            "dns_logs": 0,
            "alerts": 0,
            "incidents": 0,
            "validation_results": 0,
            "scan_results": 0,
            "file_events": 0,
            "process_events": 0,
            "log_events": 0,
            "failed_attempts": 0,
            "cve_matches": 0,
            "unique_devices": 0,
            "online_devices": 0,
            "offline_devices": 0,
            "unknown_devices": 0,
            "grouped_alerts": 0,
            "risk_score": 0,
        }
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
        row = fetch_one(f"SELECT COUNT(*) AS count FROM {table} {where}", params)
        summary[table] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE is_inventory_device = 1 AND session_id = ?", params)
    summary["unique_devices"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE is_inventory_device = 1 AND online_status = 'online' AND session_id = ?", params)
    summary["online_devices"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE is_inventory_device = 1 AND online_status != 'online' AND session_id = ?", params)
    summary["offline_devices"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM devices WHERE is_inventory_device = 1 AND trust_status = 'unknown' AND session_id = ?", params)
    summary["unknown_devices"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COUNT(*) AS count FROM (SELECT alert_type, entity FROM alerts WHERE session_id = ? GROUP BY alert_type, entity)", params)
    summary["grouped_alerts"] = int(row["count"] if row else 0)
    row = fetch_one("SELECT COALESCE(MAX(risk_score), 0) AS score FROM devices WHERE is_inventory_device = 1 AND session_id = ?", params)
    summary["risk_score"] = int(row["score"] if row else 0)
    return summary
