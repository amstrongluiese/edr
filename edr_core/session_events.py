from __future__ import annotations

from typing import Any

from .db import execute, json_dumps, utc_now
from .sessions import get_current_session_id


def record_session_event(event_type: str, entity: str | None, evidence: dict[str, Any], severity: str = "Informational") -> None:
    execute(
        """
        INSERT INTO session_events(session_id, timestamp, event_type, entity, severity, evidence)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (get_current_session_id(), utc_now(), event_type, entity, severity, json_dumps(evidence)),
    )

