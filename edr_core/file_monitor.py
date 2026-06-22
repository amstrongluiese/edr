from __future__ import annotations

from pathlib import Path

from .config import MONITORED_EXTENSIONS
from .db import init_db, utc_now
from .detection import analyze_event
from .full_scan import scan_roots, sha256_file
from .ingestion import ingest


def snapshot_monitored_files(limit_per_root: int = 500) -> int:
    init_db()
    count = 0
    for root in scan_roots():
        scanned = 0
        for path in root.rglob("*"):
            if scanned >= limit_per_root:
                break
            if not path.is_file() or path.suffix.lower() not in MONITORED_EXTENSIONS:
                continue
            scanned += 1
            event = ingest(
                {
                    "event_type": "file_event",
                    "timestamp": utc_now(),
                    "file_path": str(path),
                    "sha256": sha256_file(path),
                    "signed": None,
                    "source": "file_monitor_snapshot",
                }
            )
            analyze_event(event)
            count += 1
    return count


def main() -> None:
    print(f"Recorded {snapshot_monitored_files()} monitored file observations.")


if __name__ == "__main__":
    main()

