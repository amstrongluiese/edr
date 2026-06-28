from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from edr_engine.core.events import SensorEvent


class EventParseError(ValueError):
    """Raised when a sensor event cannot be parsed or validated."""


def parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def event_from_mapping(data: dict[str, Any]) -> SensorEvent:
    required = {
        "schema_version",
        "event_id",
        "event_type",
        "asset_id",
        "timestamp_utc",
        "source",
        "payload",
    }
    missing = sorted(required - data.keys())
    if missing:
        raise EventParseError(f"missing required fields: {', '.join(missing)}")

    payload = data["payload"]
    if not isinstance(payload, dict):
        raise EventParseError("payload must be an object")

    return SensorEvent(
        schema_version=str(data["schema_version"]),
        event_id=str(data["event_id"]),
        event_type=str(data["event_type"]),
        asset_id=str(data["asset_id"]),
        timestamp_utc=parse_timestamp(str(data["timestamp_utc"])),
        source=str(data["source"]),
        payload=payload,
    )


def iter_jsonl_events(path: Path) -> Iterable[SensorEvent]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield event_from_mapping(json.loads(stripped))
            except (json.JSONDecodeError, EventParseError, ValueError) as exc:
                raise EventParseError(f"{path}:{line_number}: {exc}") from exc
