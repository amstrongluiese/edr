from __future__ import annotations

import argparse
from pathlib import Path

from edr_engine.app import build_engine
from edr_engine.core.parsing import iter_jsonl_events


def default_migrations_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "database" / "migrations"


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest C++ sensor JSONL into SQLite.")
    parser.add_argument("jsonl", type=Path, help="Path to sensor JSONL events.")
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("data") / "edr.sqlite",
        help="SQLite database path.",
    )
    parser.add_argument(
        "--migrations",
        type=Path,
        default=default_migrations_dir(),
        help="Database migrations directory.",
    )
    args = parser.parse_args()

    engine, store = build_engine(args.db, args.migrations)
    ingested = 0
    findings = 0
    alerts = 0

    try:
        for event in iter_jsonl_events(args.jsonl):
            result = engine.ingest(event)
            ingested += 1
            findings += len(result.findings)
            alerts += len(result.alerts)
    finally:
        store.close()

    print(f"Ingested {ingested} events, created {findings} findings and {alerts} alerts, stored results in {args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
