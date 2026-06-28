from __future__ import annotations

from typing import Protocol

from edr_engine.core.events import DetectionFinding, SensorEvent
from edr_engine.reports.interfaces import ReportArtifact
from edr_engine.threat_intel.interfaces import IntelResult


class SensorEventRepository(Protocol):
    def save(self, event: SensorEvent) -> None:
        ...


class DetectionFindingRepository(Protocol):
    def save(self, finding: DetectionFinding) -> None:
        ...


class ThreatIntelRepository(Protocol):
    def save(self, result: IntelResult) -> None:
        ...


class ReportRepository(Protocol):
    def save(self, report: ReportArtifact) -> None:
        ...
