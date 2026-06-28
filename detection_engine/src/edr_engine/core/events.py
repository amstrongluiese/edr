from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SensorEvent:
    schema_version: str
    event_id: str
    event_type: str
    asset_id: str
    timestamp_utc: datetime
    source: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class DetectionFinding:
    finding_id: str
    event_id: str
    provider_id: str
    title: str
    severity: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class DetectionAlert:
    alert_id: str
    finding_id: str
    event_id: str
    device_id: str
    title: str
    description: str
    severity: str
    risk_score: int
    provider_id: str
    created_at_utc: datetime
    mitre_mappings: list[str]
    metadata: dict[str, Any]


@dataclass(frozen=True)
class RiskAssessment:
    risk_id: str
    event_id: str
    asset_id: str
    score: int
    severity: str
    reasons: list[str]
    created_at_utc: datetime
