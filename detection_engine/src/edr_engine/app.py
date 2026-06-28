from __future__ import annotations

from pathlib import Path

from edr_engine.detection.behavioral import BehavioralAnalysisProvider
from edr_engine.detection.cve import CveMatchingProvider
from edr_engine.detection.dns import DnsAnalysisProvider
from edr_engine.detection.network_rules import NetworkRulesProvider
from edr_engine.detection.threat_intel import ThreatIntelCorrelationProvider
from edr_engine.detection.unknown_device import UnknownDeviceProvider
from edr_engine.engine import DetectionEngine
from edr_engine.mitre.mapper import StaticMitreMapper
from edr_engine.storage.sqlite_store import SQLiteStore


def build_engine(db_path: Path, migrations_dir: Path) -> tuple[DetectionEngine, SQLiteStore]:
    store = SQLiteStore(db_path)
    store.apply_migrations(migrations_dir)
    mapper = StaticMitreMapper()
    engine = DetectionEngine(
        events=store,
        findings=store,
        assets=store,
        risks=store,
        alerts=store,
        mitre=store,
        mapper=mapper,
        providers=[
            UnknownDeviceProvider(store),
            BehavioralAnalysisProvider(),
            DnsAnalysisProvider(),
            NetworkRulesProvider(),
            ThreatIntelCorrelationProvider(store),
            CveMatchingProvider(store),
        ],
    )
    return engine, store
