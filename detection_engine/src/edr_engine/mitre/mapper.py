from __future__ import annotations

from edr_engine.core.events import DetectionFinding, SensorEvent
from edr_engine.mitre.attack_mapping import AttackMappingEngine
from edr_engine.mitre.interfaces import MitreMapper, MitreTechnique


class StaticMitreMapper(MitreMapper):
    def __init__(self, mapping_engine: AttackMappingEngine | None = None) -> None:
        self._mapping_engine = mapping_engine or AttackMappingEngine()

    def map_event(self, event: SensorEvent) -> list[MitreTechnique]:
        if event.event_type == "process.created":
            return [MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution")]
        if event.event_type == "network.connection_observed":
            return [MitreTechnique("T1071", "Application Layer Protocol", "Command and Control")]
        if event.event_type.startswith("dns."):
            return [MitreTechnique("T1071.004", "DNS", "Command and Control")]
        return []

    def map_finding(self, finding: DetectionFinding) -> list[MitreTechnique]:
        category = str(finding.metadata.get("category", ""))
        return self._mapping_engine.map_category(category, finding.metadata)
