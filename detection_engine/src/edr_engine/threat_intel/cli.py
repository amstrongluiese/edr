from __future__ import annotations

import argparse
from pathlib import Path

from edr_engine.storage.sqlite_store import SQLiteStore
from edr_engine.threat_intel.cache_importer import import_cache_to_sqlite


def default_migrations_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "database" / "migrations"


def main() -> int:
    parser = argparse.ArgumentParser(description="Import offline threat-intel cache files into SQLite.")
    parser.add_argument("--cache-dir", type=Path, default=Path("threat_intel"), help="Threat-intel cache directory.")
    parser.add_argument("--db", type=Path, default=Path("data") / "edr.sqlite", help="SQLite database path.")
    parser.add_argument("--migrations", type=Path, default=default_migrations_dir(), help="Database migrations directory.")
    args = parser.parse_args()

    store = SQLiteStore(args.db)
    try:
        store.apply_migrations(args.migrations)
    finally:
        store.close()

    count = import_cache_to_sqlite(args.cache_dir, args.db)
    print(f"Imported {count} threat intelligence indicators into {args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
