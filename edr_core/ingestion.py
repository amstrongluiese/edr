from __future__ import annotations

import json
from typing import Any

from .db import execute, fetch_one, json_dumps, utc_now
from .models import NormalizedEvent
from .sessions import get_current_session_id


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_event(raw: dict[str, Any]) -> NormalizedEvent:
    event_type = str(raw.get("event_type") or raw.get("type") or "connection").lower()
    timestamp = str(raw.get("timestamp") or utc_now())
    port = _int_or_none(raw.get("port") or raw.get("destination_port"))
    source_port = _int_or_none(raw.get("source_port") or raw.get("local_port"))
    bytes_sent = int(raw.get("bytes_sent") or 0)
    bytes_received = int(raw.get("bytes_received") or 0)
    bytes_total = int(raw.get("bytes_total") or bytes_sent + bytes_received)
    open_ports = raw.get("open_ports") or []
    if isinstance(open_ports, str):
        open_ports = [int(p.strip()) for p in open_ports.split(",") if p.strip().isdigit()]

    software = raw.get("software") or []
    if isinstance(software, dict):
        software = [software]

    return NormalizedEvent(
        event_type=event_type,
        timestamp=timestamp,
        source_ip=raw.get("source_ip"),
        destination_ip=raw.get("destination_ip") or raw.get("dest_ip"),
        port=port,
        source_port=source_port,
        direction=raw.get("direction"),
        protocol=raw.get("protocol"),
        process_name=raw.get("process_name") or raw.get("process"),
        pid=_int_or_none(raw.get("pid")),
        domain=raw.get("domain") or raw.get("query"),
        query_type=raw.get("query_type"),
        resolved_ip=raw.get("resolved_ip"),
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        bytes_total=bytes_total,
        window_seconds=int(raw.get("window_seconds") or 60),
        ip=raw.get("ip") or raw.get("source_ip"),
        mac=raw.get("mac"),
        hostname=raw.get("hostname"),
        vendor=raw.get("vendor"),
        device_type=raw.get("device_type"),
        trust_status=raw.get("trust_status") or "unknown",
        online_status=raw.get("online_status") or "online",
        discovery_source=raw.get("discovery_source") or raw.get("source") or "telemetry",
        open_ports=open_ports,
        software=software,
        file_hash=raw.get("file_hash") or raw.get("sha256"),
        file_path=raw.get("file_path") or raw.get("path") or raw.get("executable_path"),
        command_line=raw.get("command_line"),
        parent_process=raw.get("parent_process"),
        signed=raw.get("signed"),
        username=raw.get("username"),
        outcome=raw.get("outcome"),
        target_system=raw.get("target_system"),
        log_source=raw.get("log_source") or raw.get("source"),
        url=raw.get("url"),
        raw=raw,
    )


def _device_key(ip: str | None, mac: str | None, hostname: str | None) -> str:
    normalized_mac = (mac or "").strip().lower().replace("-", ":")
    if normalized_mac and normalized_mac != "ff:ff:ff:ff:ff:ff":
        return f"mac:{normalized_mac}"
    hostname_part = (hostname or "").strip().lower()
    return f"iphost:{ip or ''}|{hostname_part}"


def _is_inventory_device(ip: str | None, mac: str | None, discovery_source: str | None) -> int:
    source = (discovery_source or "").lower()
    if not ip:
        return 0
    if ip == "local-endpoint":
        return 0
    if ip.startswith(("10.240.", "10.241.", "198.51.100.", "203.0.113.", "192.0.2.", "224.", "239.", "255.", "0.", "127.", "169.254.")):
        return 0
    if mac:
        return 1
    visible_sources = {"arp_table", "windows_neighbor_table", "ping_sweep", "subnet_scan", "post_ping_arp", "device_discovery"}
    if any(item in source for item in visible_sources):
        return 1
    return 0


def persist_event(event: NormalizedEvent) -> None:
    session_id = get_current_session_id()
    if event.event_type in {"device", "device_seen"} and event.ip:
        device_key = _device_key(event.ip, event.mac, event.hostname)
        is_inventory = _is_inventory_device(event.ip, event.mac, event.discovery_source)
        if event.mac:
            existing = fetch_one("SELECT id FROM devices WHERE lower(replace(mac, '-', ':')) = lower(replace(?, '-', ':'))", (event.mac,))
            if existing:
                execute(
                    """
                    UPDATE devices
                    SET ip = ?,
                        hostname = COALESCE(?, hostname),
                        vendor = COALESCE(?, vendor),
                        device_type = COALESCE(?, device_type),
                        last_seen = ?,
                        trust_status = ?,
                        online_status = ?,
                        discovery_source = ?,
                        device_key = ?,
                        is_inventory_device = ?
                        , session_id = ?
                    WHERE id = ?
                    """,
                    (
                        event.ip,
                        event.hostname,
                        event.vendor,
                        event.device_type,
                        event.timestamp,
                        event.trust_status,
                        event.online_status,
                        event.discovery_source,
                        device_key,
                        is_inventory,
                        session_id,
                        existing["id"],
                    ),
                )
                return
        execute(
            """
            INSERT INTO devices(ip, mac, hostname, vendor, device_type, first_seen, last_seen,
                                trust_status, online_status, discovery_source, device_key, is_inventory_device, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac=COALESCE(excluded.mac, devices.mac),
                hostname=COALESCE(excluded.hostname, devices.hostname),
                vendor=COALESCE(excluded.vendor, devices.vendor),
                device_type=COALESCE(excluded.device_type, devices.device_type),
                last_seen=excluded.last_seen,
                trust_status=excluded.trust_status,
                online_status=excluded.online_status,
                discovery_source=excluded.discovery_source,
                device_key=excluded.device_key,
                is_inventory_device=excluded.is_inventory_device
                , session_id=excluded.session_id
            """,
            (
                event.ip,
                event.mac,
                event.hostname,
                event.vendor,
                event.device_type,
                event.timestamp,
                event.timestamp,
                event.trust_status,
                event.online_status,
                event.discovery_source,
                device_key,
                is_inventory,
                session_id,
            ),
        )
    elif event.event_type in {"dns", "dns_query"} and event.domain:
        _observe_ip(event.source_ip, event.timestamp, "passive_network_observation")
        execute(
            """
            INSERT INTO dns_logs(timestamp, source_ip, domain, query_type, resolved_ip, raw_event, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.source_ip,
                event.domain,
                event.query_type,
                event.resolved_ip,
                json_dumps(event.raw),
                session_id,
            ),
        )
    elif event.event_type in {"traffic", "traffic_window"}:
        _observe_ip(event.source_ip, event.timestamp, "passive_network_observation")
        _observe_ip(event.destination_ip, event.timestamp, "passive_network_observation")
        execute(
            """
            INSERT INTO traffic_logs(timestamp, source_ip, destination_ip, bytes_total, window_seconds, raw_event, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.source_ip,
                event.destination_ip,
                event.bytes_total,
                event.window_seconds,
                json_dumps(event.raw),
                session_id,
            ),
        )
    elif event.event_type in {"file", "file_event", "file_scan"} and event.file_path:
        extension = ""
        if "." in event.file_path:
            extension = "." + event.file_path.rsplit(".", 1)[-1].lower()
        execute(
            """
            INSERT INTO file_events(timestamp, path, extension, sha256, signed_status, source, risk_score, evidence, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.file_path,
                extension,
                event.file_hash,
                "signed" if event.signed else "unsigned_or_unknown",
                event.log_source or event.event_type,
                0,
                json_dumps(event.raw),
                session_id,
            ),
        )
    elif event.event_type in {"process", "process_event", "process_scan"}:
        execute(
            """
            INSERT INTO process_events(timestamp, process_name, pid, parent_process, command_line,
                                       executable_path, sha256, signed_status, source, evidence, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.process_name,
                event.pid,
                event.parent_process,
                event.command_line,
                event.file_path,
                event.file_hash,
                "signed" if event.signed else "unsigned_or_unknown",
                event.log_source or event.event_type,
                json_dumps(event.raw),
                session_id,
            ),
        )
    elif event.event_type in {"auth_log", "access_log", "database_log", "server_log", "application_log"}:
        _observe_ip(event.source_ip, event.timestamp, "log_observation")
        execute(
            """
            INSERT INTO log_events(timestamp, log_source, event_type, username, source_ip, device,
                                   target_system, outcome, raw_event, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.log_source or "imported_log",
                event.event_type,
                event.username,
                event.source_ip,
                event.hostname,
                event.target_system,
                event.outcome,
                json_dumps(event.raw),
                session_id,
            ),
        )
    else:
        _observe_ip(event.source_ip, event.timestamp, "passive_network_observation")
        _observe_ip(event.destination_ip, event.timestamp, "passive_network_observation")
        execute(
            """
            INSERT INTO connections(timestamp, process_name, pid, source_ip, destination_ip, source_port, port, protocol,
                                    direction, bytes_sent, bytes_received, event_type, raw_event, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.process_name,
                event.pid,
                event.source_ip,
                event.destination_ip,
                event.source_port,
                event.port,
                event.protocol,
                event.direction,
                event.bytes_sent,
                event.bytes_received,
                event.event_type,
                json_dumps(event.raw),
                session_id,
            ),
        )


def _observe_ip(ip: str | None, timestamp: str, source: str) -> None:
    if not ip or ip.startswith("127.") or ip == "0.0.0.0":
        return
    existing = fetch_one("SELECT discovery_source FROM devices WHERE ip = ?", (ip,))
    merged_source = source
    if existing and existing["discovery_source"]:
        parts = {part for part in str(existing["discovery_source"]).split(",") if part}
        parts.add(source)
        merged_source = ",".join(sorted(parts))
    execute(
        """
        INSERT INTO devices(ip, first_seen, last_seen, trust_status, risk_level, risk_score, online_status, discovery_source, device_key, is_inventory_device, session_id)
        VALUES (?, ?, ?, 'unknown', 'Informational', 0, 'online', ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            last_seen=excluded.last_seen,
            online_status='online',
            discovery_source=excluded.discovery_source,
            device_key=COALESCE(devices.device_key, excluded.device_key),
            is_inventory_device=MAX(devices.is_inventory_device, excluded.is_inventory_device)
            , session_id=excluded.session_id
        """,
        (ip, timestamp, timestamp, merged_source, _device_key(ip, None, None), _is_inventory_device(ip, None, merged_source), get_current_session_id()),
    )


def ingest(raw: dict[str, Any]) -> NormalizedEvent:
    event = normalize_event(raw)
    persist_event(event)
    return event


def parse_json_line(line: str) -> dict[str, Any]:
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid telemetry JSON: {exc}") from exc
