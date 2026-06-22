from __future__ import annotations

from datetime import datetime, timezone

from .db import execute, fetch_all, fetch_one, json_dumps, utc_now
from .device_discovery import discover_from_arp_table, discover_from_neighbor_table
from .detection import analyze_event
from .ingestion import _device_key, ingest
from .session_events import record_session_event
from .sessions import get_current_session_id


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def scan_presence(offline_after_seconds: int = 25) -> dict[str, int]:
    """Fast live presence scan for the current session using ARP and neighbor tables."""
    session_id = get_current_session_id()
    if not session_id:
        return {"seen": 0, "offline": 0, "changed_ip": 0}

    now = utc_now()
    discovered = discover_from_arp_table() + discover_from_neighbor_table()
    seen_keys: set[str] = set()
    changed_ip = 0

    for raw in discovered:
        key = _device_key(raw.get("ip"), raw.get("mac"), raw.get("hostname"))
        seen_keys.add(key)
        existing = fetch_one("SELECT * FROM devices WHERE session_id = ? AND device_key = ?", (session_id, key))
        if existing and existing["ip"] != raw.get("ip"):
            changed_ip += 1
            record_session_event(
                "device_ip_changed",
                raw.get("mac") or key,
                {"old_ip": existing["ip"], "new_ip": raw.get("ip"), "mac": raw.get("mac"), "hostname": raw.get("hostname")},
            )
        if not existing or existing["online_status"] != "online":
            record_session_event("device_online", raw.get("ip"), raw)
        event = ingest({**raw, "online_status": "online", "discovery_source": raw.get("discovery_source", "live_presence")})
        analyze_event(event)

    offline = 0
    rows = fetch_all("SELECT id, ip, mac, hostname, last_seen, online_status FROM devices WHERE session_id = ? AND is_inventory_device = 1", (session_id,))
    current = datetime.now(timezone.utc)
    for row in rows:
        key = _device_key(row["ip"], row["mac"], row["hostname"])
        age = (current - _parse_ts(row["last_seen"])).total_seconds()
        if key not in seen_keys and age >= offline_after_seconds and row["online_status"] != "offline":
            execute("UPDATE devices SET online_status = 'offline' WHERE id = ?", (row["id"],))
            record_session_event(
                "device_offline",
                row["ip"],
                {"ip": row["ip"], "mac": row["mac"], "hostname": row["hostname"], "last_seen": row["last_seen"], "offline_after_seconds": offline_after_seconds},
            )
            offline += 1
        elif key not in seen_keys and row["online_status"] == "online" and age >= max(5, offline_after_seconds // 2):
            execute("UPDATE devices SET online_status = 'recently_seen' WHERE id = ?", (row["id"],))
            record_session_event(
                "device_recently_seen",
                row["ip"],
                {"ip": row["ip"], "mac": row["mac"], "hostname": row["hostname"], "last_seen": row["last_seen"]},
            )

    execute(
        "INSERT INTO performance_metrics(timestamp, metric_name, metric_value, unit, context, session_id) VALUES (?, ?, ?, ?, ?, ?)",
        (now, "live_presence_scan", len(discovered), "devices", json_dumps({"offline_marked": offline, "ip_changes": changed_ip}), session_id),
    )
    return {"seen": len(discovered), "offline": offline, "changed_ip": changed_ip}

