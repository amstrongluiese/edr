from __future__ import annotations

from typing import Iterable, Protocol
from uuid import uuid4

from edr_engine.core.events import DetectionFinding, SensorEvent
from edr_engine.core.ports import DetectionProvider
from edr_engine.threat_intel.interfaces import IntelResult, Observable
from edr_engine.threat_intel.observables import extract_observables


class ThreatIntelLookup(Protocol):
    def lookup_threat_intel(self, observables: list[Observable]) -> list[IntelResult]:
        ...


REPUTATION_SEVERITY = {
    "malicious": "critical",
    "suspicious": "high",
    "unknown": "low",
    "benign": "info",
}

REPUTATION_RISK_POINTS = {
    "malicious": 40,
    "suspicious": 25,
    "unknown": 5,
    "benign": 0,
}


class ThreatIntelCorrelationProvider(DetectionProvider):
    def __init__(self, lookup: ThreatIntelLookup) -> None:
        self._lookup = lookup

    @property
    def provider_id(self) -> str:
        return "threat_intel_correlation"

    def evaluate(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        results = self._lookup.lookup_threat_intel(extract_observables(event))
        for result in results:
            reputation = result.reputation.lower()
            if reputation == "benign":
                continue
            observable = result.observable
            cve_severity = str(result.metadata.get("cve_severity") or "").lower()
            cve_points = {"critical": 50, "high": 35, "medium": 20, "low": 10}
            risk_points = cve_points.get(cve_severity, REPUTATION_RISK_POINTS.get(reputation, 5))
            summary = str(result.metadata.get("summary") or "")
            if not summary:
                summary = f"{observable.kind}:{observable.value} matched {result.source} as {reputation}"
            yield DetectionFinding(
                finding_id=str(uuid4()),
                event_id=event.event_id,
                provider_id=self.provider_id,
                title=f"Threat intelligence match for {observable.kind}",
                severity=REPUTATION_SEVERITY.get(reputation, "medium"),
                metadata={
                    "category": f"threat_intel_{observable.kind}",
                    "basis": summary,
                    "observable_kind": observable.kind,
                    "observable_value": observable.value,
                    "source": result.source,
                    "reputation": reputation,
                    "cve_id": result.metadata.get("cve_id", ""),
                    "cve_severity": cve_severity,
                    "risk_points": risk_points,
                    "threat_intel": result.metadata,
                },
            )
