from __future__ import annotations

import hashlib
import json

from .db import connect, init_db, json_dumps
from .ingestion import _device_key, _is_inventory_device


def _hash_evidence(evidence: str) -> str:
    try:
        canonical = json_dumps(json.loads(evidence or "{}"))
    except json.JSONDecodeError:
        canonical = evidence or "{}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def repair_alert_grouping() -> int:
    init_db()
    removed = 0
    with connect() as conn:
        rows = conn.execute("SELECT id, timestamp, evidence FROM alerts").fetchall()
        for row in rows:
            conn.execute(
                """
                UPDATE alerts
                SET first_seen = COALESCE(first_seen, ?),
                    last_seen = COALESCE(last_seen, ?),
                    evidence_hash = COALESCE(evidence_hash, ?),
                    occurrence_count = CASE WHEN occurrence_count < 1 THEN 1 ELSE occurrence_count END
                WHERE id = ?
                """,
                (row["timestamp"], row["timestamp"], _hash_evidence(row["evidence"]), row["id"]),
            )

        groups = conn.execute(
            """
            SELECT alert_type, entity, evidence_hash, COUNT(*) AS row_count
            FROM alerts
            WHERE evidence_hash IS NOT NULL
            GROUP BY alert_type, entity, evidence_hash
            HAVING COUNT(*) > 1
            """
        ).fetchall()
        for group in groups:
            members = conn.execute(
                """
                SELECT *
                FROM alerts
                WHERE alert_type = ? AND entity = ? AND evidence_hash = ?
                ORDER BY id
                """,
                (group["alert_type"], group["entity"], group["evidence_hash"]),
            ).fetchall()
            keeper = members[0]
            member_ids = [row["id"] for row in members]
            first_seen = min(row["first_seen"] or row["timestamp"] for row in members)
            last_seen = max(row["last_seen"] or row["timestamp"] for row in members)
            occurrence_count = sum(int(row["occurrence_count"] or 1) for row in members)
            max_score = max(int(row["score"]) for row in members)
            severity = max(members, key=lambda row: int(row["score"]))["severity"]
            conn.execute(
                """
                UPDATE alerts
                SET first_seen = ?, last_seen = ?, timestamp = ?, occurrence_count = ?,
                    score = ?, severity = ?, status = 'grouped'
                WHERE id = ?
                """,
                (first_seen, last_seen, last_seen, occurrence_count, max_score, severity, keeper["id"]),
            )
            for alert_id in member_ids[1:]:
                conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
                removed += 1
    return removed


def repair_device_inventory() -> dict[str, int]:
    init_db()
    removed = 0
    updated = 0
    with connect() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY id").fetchall()
        for row in rows:
            key = _device_key(row["ip"], row["mac"], row["hostname"])
            inventory = _is_inventory_device(row["ip"], row["mac"], row["discovery_source"])
            conn.execute(
                "UPDATE devices SET device_key = ?, is_inventory_device = ? WHERE id = ?",
                (key, inventory, row["id"]),
            )
            updated += 1

        groups = conn.execute(
            """
            SELECT device_key, COUNT(*) AS row_count
            FROM devices
            WHERE device_key IS NOT NULL AND device_key != ''
            GROUP BY device_key
            HAVING COUNT(*) > 1
            """
        ).fetchall()
        for group in groups:
            members = conn.execute("SELECT * FROM devices WHERE device_key = ? ORDER BY last_seen DESC, id", (group["device_key"],)).fetchall()
            keeper = members[0]
            best = {
                "ip": keeper["ip"],
                "mac": keeper["mac"],
                "hostname": keeper["hostname"],
                "vendor": keeper["vendor"],
                "device_type": keeper["device_type"],
                "first_seen": min(row["first_seen"] for row in members),
                "last_seen": max(row["last_seen"] for row in members),
                "trust_status": "trusted" if any(row["trust_status"] == "trusted" for row in members) else keeper["trust_status"],
                "risk_score": max(int(row["risk_score"]) for row in members),
                "online_status": "online" if any(row["online_status"] == "online" for row in members) else "offline",
                "discovery_source": ",".join(sorted({part for row in members for part in str(row["discovery_source"] or "").split(",") if part})),
                "is_inventory_device": _is_inventory_device(keeper["ip"], keeper["mac"], keeper["discovery_source"]),
            }
            risk_level = "Critical" if best["risk_score"] > 80 else "High Risk" if best["risk_score"] > 60 else "Suspicious" if best["risk_score"] > 30 else "Low Risk" if best["risk_score"] > 10 else "Informational"
            conn.execute(
                """
                UPDATE devices
                SET ip = ?, mac = COALESCE(?, mac), hostname = COALESCE(?, hostname),
                    vendor = COALESCE(?, vendor), device_type = COALESCE(?, device_type),
                    first_seen = ?, last_seen = ?, trust_status = ?, risk_level = ?,
                    risk_score = ?, online_status = ?, discovery_source = ?, is_inventory_device = ?
                WHERE id = ?
                """,
                (
                    best["ip"],
                    best["mac"],
                    best["hostname"],
                    best["vendor"],
                    best["device_type"],
                    best["first_seen"],
                    best["last_seen"],
                    best["trust_status"],
                    risk_level,
                    best["risk_score"],
                    best["online_status"],
                    best["discovery_source"],
                    best["is_inventory_device"],
                    keeper["id"],
                ),
            )
            for row in members[1:]:
                conn.execute("DELETE FROM devices WHERE id = ?", (row["id"],))
                removed += 1
    return {"updated": updated, "removed": removed}


def repair_all() -> dict[str, object]:
    return {
        "alerts_removed": repair_alert_grouping(),
        "devices": repair_device_inventory(),
    }


def main() -> None:
    print(repair_all())


if __name__ == "__main__":
    main()
