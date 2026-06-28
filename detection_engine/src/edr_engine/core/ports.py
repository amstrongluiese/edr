from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Protocol

from edr_engine.core.events import DetectionAlert, DetectionFinding, RiskAssessment, SensorEvent


class EventIngestionPort(ABC):
    @abstractmethod
    def ingest(self, event: SensorEvent) -> None:
        """Accept a validated sensor event for processing."""


class DetectionProvider(ABC):
    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Stable provider identifier."""

    @abstractmethod
    def evaluate(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        """Return findings for an event. Implementations are added later."""


class EventRepository(Protocol):
    def save_event(self, event: SensorEvent) -> None:
        ...


class FindingRepository(Protocol):
    def save_finding(self, finding: DetectionFinding) -> None:
        ...


class AlertRepository(Protocol):
    def save_alert(self, alert: DetectionAlert) -> None:
        ...

    def correlate_alerts(self, alerts: list[DetectionAlert]) -> None:
        ...


class AssetRepository(Protocol):
    def exists(self, asset_id: str) -> bool:
        ...

    def upsert_seen(self, event: SensorEvent) -> None:
        ...


class RiskRepository(Protocol):
    def save_risk(self, risk: RiskAssessment) -> None:
        ...
