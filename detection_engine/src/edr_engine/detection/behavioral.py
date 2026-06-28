from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Iterable
from uuid import uuid4

from edr_engine.core.events import DetectionFinding, SensorEvent
from edr_engine.core.ports import DetectionProvider


SCRIPTING_AND_LOLBIN_NAMES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}


class BehavioralAnalysisProvider(DetectionProvider):
    @property
    def provider_id(self) -> str:
        return "behavioral"

    def evaluate(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        if event.event_type == "process.created":
            yield from self._evaluate_process(event)
        elif event.event_type == "network.connection_observed":
            yield from self._evaluate_network(event)

    def _evaluate_process(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        image_name = str(event.payload.get("image_name", "")).lower()
        executable = PureWindowsPath(image_name).name.lower()

        if executable in SCRIPTING_AND_LOLBIN_NAMES:
            yield self._finding(
                event,
                "Suspicious process family observed",
                "medium",
                {
                    "image_name": image_name,
                    "category": "living_off_the_land_or_scripting",
                },
            )

        if "\\temp\\" in image_name or "\\appdata\\local\\temp\\" in image_name:
            yield self._finding(
                event,
                "Process executed from temporary directory",
                "medium",
                {
                    "image_name": image_name,
                    "category": "unusual_execution_location",
                },
            )

        if self._is_unknown_process(event):
            yield self._finding(
                event,
                "Unknown process observed",
                "medium",
                {
                    "image_name": image_name or "Unknown",
                    "basis": "Process telemetry marked the executable as unknown, unsigned, or untrusted",
                    "category": "unknown_process",
                },
            )

    def _evaluate_network(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        state = str(event.payload.get("state", "")).upper()
        remote_port = int(event.payload.get("remote_port") or 0)

        if state == "ESTABLISHED" and remote_port in {4444, 5555, 6666, 1337, 31337}:
            yield self._finding(
                event,
                "Connection to commonly abused remote port",
                "high",
                {
                    "remote_port": remote_port,
                    "state": state,
                    "category": "suspicious_network_port",
                },
            )

    def _is_unknown_process(self, event: SensorEvent) -> bool:
        known_flag = event.payload.get("known_process")
        trusted_flag = event.payload.get("trusted")
        signature_status = str(event.payload.get("signature_status", "")).lower()
        reputation = str(event.payload.get("reputation", "")).lower()

        if known_flag is False or trusted_flag is False:
            return True
        if signature_status in {"unknown", "unsigned", "invalid", "untrusted"}:
            return True
        return reputation in {"unknown", "suspicious", "untrusted"}

    def _finding(
        self,
        event: SensorEvent,
        title: str,
        severity: str,
        metadata: dict,
    ) -> DetectionFinding:
        return DetectionFinding(
            finding_id=str(uuid4()),
            event_id=event.event_id,
            provider_id=self.provider_id,
            title=title,
            severity=severity,
            metadata=metadata,
        )
