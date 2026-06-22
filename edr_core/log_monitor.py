from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from .db import init_db, utc_now
from .detection import analyze_event
from .ingestion import ingest


IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")


def _event_from_row(row: dict[str, str], source: str) -> dict[str, Any]:
    text = " ".join(str(value) for value in row.values())
    ip_match = IP_RE.search(text)
    outcome = (row.get("outcome") or row.get("status") or row.get("result") or "").lower()
    if not outcome:
        if any(token in text.lower() for token in ["failed", "failure", "denied", "invalid password"]):
            outcome = "failed"
        elif any(token in text.lower() for token in ["success", "accepted", "login ok"]):
            outcome = "success"
    target = row.get("target_system") or row.get("service") or row.get("database") or row.get("application") or source
    event_type = "database_log" if "database" in target.lower() or "db" in target.lower() else "auth_log"
    return {
        "event_type": event_type,
        "timestamp": row.get("timestamp") or row.get("time") or utc_now(),
        "log_source": source,
        "username": row.get("username") or row.get("user") or row.get("account"),
        "source_ip": row.get("source_ip") or row.get("ip") or (ip_match.group("ip") if ip_match else None),
        "hostname": row.get("device") or row.get("host"),
        "target_system": target,
        "outcome": outcome,
        "raw": row,
    }


def import_log_file(path: Path, source: str | None = None) -> int:
    init_db()
    source_name = source or path.name
    count = 0
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return 0
    if "," in lines[0]:
        for row in csv.DictReader(lines):
            event = ingest(_event_from_row(row, source_name))
            analyze_event(event)
            count += 1
    else:
        for line in lines:
            ip_match = IP_RE.search(line)
            lower = line.lower()
            outcome = "failed" if any(token in lower for token in ["failed", "failure", "denied"]) else "success" if "success" in lower else ""
            event = ingest(
                {
                    "event_type": "auth_log",
                    "timestamp": utc_now(),
                    "log_source": source_name,
                    "username": "",
                    "source_ip": ip_match.group("ip") if ip_match else None,
                    "target_system": source_name,
                    "outcome": outcome,
                    "raw_line": line,
                }
            )
            analyze_event(event)
            count += 1
    return count


def main() -> None:
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m edr_core.log_monitor <log-file>")
        raise SystemExit(2)
    print(f"Imported {import_log_file(Path(sys.argv[1]))} log events.")


if __name__ == "__main__":
    main()

