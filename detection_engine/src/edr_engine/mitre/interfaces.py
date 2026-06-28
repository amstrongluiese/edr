from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from edr_engine.core.events import DetectionFinding, SensorEvent


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str


class MitreMapper(ABC):
    @abstractmethod
    def map_event(self, event: SensorEvent) -> list[MitreTechnique]:
        """Map an event to candidate techniques."""

    @abstractmethod
    def map_finding(self, finding: DetectionFinding) -> list[MitreTechnique]:
        """Map a detection finding to candidate techniques."""
