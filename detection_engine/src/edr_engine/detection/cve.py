from __future__ import annotations

from typing import Iterable, Protocol
from uuid import uuid4

from edr_engine.core.events import DetectionFinding, SensorEvent
from edr_engine.core.ports import DetectionProvider


class CveLookup(Protocol):
    def lookup_cve_matches(self, event: SensorEvent) -> list[dict]:
        ...


CVE_POINTS = {"critical": 50, "high": 35, "medium": 20, "low": 10}
CVE_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


class CveMatchingProvider(DetectionProvider):
    def __init__(self, lookup: CveLookup) -> None:
        self._lookup = lookup

    @property
    def provider_id(self) -> str:
        return "cve_matching"

    def evaluate(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        for match in self._lookup.lookup_cve_matches(event):
            cve_id = str(match.get("cve_id") or "")
            severity = str(match.get("cve_severity") or "").lower()
            if not cve_id or not severity:
                continue
            points = CVE_POINTS.get(severity, 10)
            yield DetectionFinding(
                finding_id=str(uuid4()),
                event_id=event.event_id,
                provider_id=self.provider_id,
                title=f"Vulnerable software or service matched {cve_id}",
                severity=CVE_SEVERITY.get(severity, "low"),
                metadata={
                    "category": "threat_intel_cve",
                    "basis": match.get("summary") or f"{cve_id} matched software/service telemetry",
                    "cve_id": cve_id,
                    "cve_severity": severity,
                    "cvss_score": match.get("cvss_score", 0),
                    "matched_text": match.get("matched_text", ""),
                    "observable_kind": "cve",
                    "observable_value": cve_id,
                    "source": match.get("source", "nvd:cve"),
                    "reputation": "suspicious",
                    "risk_points": points,
                    "threat_intel": match,
                },
            )
