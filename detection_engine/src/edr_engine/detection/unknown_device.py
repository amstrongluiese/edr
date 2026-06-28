from __future__ import annotations

from typing import Iterable
from uuid import uuid4

from edr_engine.core.events import DetectionFinding, SensorEvent
from edr_engine.core.ports import AssetRepository, DetectionProvider


class UnknownDeviceProvider(DetectionProvider):
    def __init__(self, assets: AssetRepository) -> None:
        self._assets = assets

    @property
    def provider_id(self) -> str:
        return "unknown_device"

    def evaluate(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        if self._assets.exists(event.asset_id):
            return []

        return [
            DetectionFinding(
                finding_id=str(uuid4()),
                event_id=event.event_id,
                provider_id=self.provider_id,
                title="Telemetry from previously unknown device",
                severity="info",
                metadata={
                    "asset_id": event.asset_id,
                    "category": "asset_inventory",
                    "basis": "First telemetry from an asset that is not yet in the local inventory",
                    "risk_points": 5,
                },
            )
        ]
