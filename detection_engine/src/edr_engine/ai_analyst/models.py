from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AnalystAlert:
    alert_id: str
    title: str
    severity: str
    device_id: str
    risk_score: int = 0
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str = "medium"


@dataclass(frozen=True)
class ThreatIntelMatch:
    observable: str
    observable_type: str
    source: str
    reputation: str
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalystIncident:
    incident_id: str
    title: str
    severity: str
    risk_score: int
    affected_device: str
    timeline: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    related_alert_ids: list[str] = field(default_factory=list)
    status: str = "open"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalystInput:
    risk_score: int
    alerts: list[AnalystAlert]
    incidents: list[AnalystIncident] = field(default_factory=list)
    mitre_mappings: list[MitreMapping] = field(default_factory=list)
    threat_intel_matches: list[ThreatIntelMatch] = field(default_factory=list)
    subject: str = "Current environment"
    generated_at_utc: datetime | None = None


@dataclass(frozen=True)
class AnalystReport:
    executive_summary: str
    technical_findings: str
    recommendations: list[str]
    incident_narrative: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def technical_analysis(self) -> str:
        return self.technical_findings
