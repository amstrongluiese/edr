import sys
from pathlib import Path

from .db import init_db
from .detection import analyze_event
from .ingestion import ingest, parse_json_line


def ingest_file(path: Path) -> int:
    init_db()
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            event = ingest(parse_json_line(line))
            analyze_event(event)
            count += 1
    return count


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m edr_core.ingest_file <telemetry.ndjson>")
        raise SystemExit(2)
    count = ingest_file(Path(sys.argv[1]))
    print(f"Ingested and analyzed {count} events.")


if __name__ == "__main__":
    main()

