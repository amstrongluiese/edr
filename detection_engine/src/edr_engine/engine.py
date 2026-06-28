from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from edr_engine.core.events import DetectionAlert, DetectionFinding, RiskAssessment, SensorEvent
from edr_engine.core.ports import (
    AlertRepository,
    AssetRepository,
    DetectionProvider,
    EventIngestionPort,
    EventRepository,
    FindingRepository,
    RiskRepository,
)
from edr_engine.core.risk import RiskScorer, risk_level_from_score
from edr_engine.mitre.interfaces import MitreMapper


class MitreRepository:
    def save_finding_mappings(self, finding: DetectionFinding, mapper: MitreMapper) -> None:
        raise NotImplementedError

    def save_alert_mappings(self, alert: DetectionAlert, mapper: MitreMapper, finding: DetectionFinding) -> None:
        raise NotImplementedError


@dataclass(frozen=True)
class IngestionResult:
    event_id: str
    findings: list[DetectionFinding]
    risk: RiskAssessment
    alerts: list[DetectionAlert]


class DetectionEngine(EventIngestionPort):
    def __init__(
        self,
        events: EventRepository,
        findings: FindingRepository,
        assets: AssetRepository,
        risks: RiskRepository,
        alerts: AlertRepository,
        mitre: MitreRepository,
        mapper: MitreMapper,
        providers: list[DetectionProvider],
        scorer: RiskScorer | None = None,
    ) -> None:
        self._events = events
        self._findings = findings
        self._assets = assets
        self._risks = risks
        self._alerts = alerts
        self._mitre = mitre
        self._mapper = mapper
        self._providers = providers
        self._scorer = scorer or RiskScorer()

    def ingest(self, event: SensorEvent) -> IngestionResult:
        findings: list[DetectionFinding] = []
        for provider in self._providers:
            findings.extend(provider.evaluate(event))

        self._events.save_event(event)

        for finding in findings:
            self._findings.save_finding(finding)
            self._mitre.save_finding_mappings(finding, self._mapper)

        risk = self._scorer.score(event, findings)
        self._risks.save_risk(risk)
        self._assets.upsert_seen(event)

        alerts = []
        for finding in findings:
            alert = self._build_alert(event, finding, risk, findings)
            self._alerts.save_alert(alert)
            self._mitre.save_alert_mappings(alert, self._mapper, finding)
            alerts.append(alert)

        if alerts:
            self._alerts.correlate_alerts(alerts)

        return IngestionResult(event.event_id, findings, risk, alerts)

    def _build_alert(
        self,
        event: SensorEvent,
        finding: DetectionFinding,
        risk: RiskAssessment,
        all_findings: list[DetectionFinding],
    ) -> DetectionAlert:
        techniques = self._mapper.map_finding(finding)
        basis = str(finding.metadata.get("basis") or finding.title)
        evidence_items = [
            {
                "category": str(item.metadata.get("category", "")),
                "title": item.title,
                "basis": str(item.metadata.get("basis") or item.title),
                "risk_points": int(item.metadata.get("risk_points") or self._scorer._finding_points(item)),
            }
            for item in all_findings
        ]
        categories = sorted({item["category"] for item in evidence_items if item["category"]})
        risk_level = risk_level_from_score(risk.score)
        return DetectionAlert(
            alert_id=str(uuid4()),
            finding_id=finding.finding_id,
            event_id=event.event_id,
            device_id=event.asset_id,
            title=finding.title,
            description=basis,
            severity=risk.severity,
            risk_score=risk.score,
            provider_id=finding.provider_id,
            created_at_utc=datetime.now(timezone.utc),
            mitre_mappings=[f"{item.technique_id} {item.name}" for item in techniques],
            metadata={
                **finding.metadata,
                "detection_basis": basis,
                "risk_level": risk_level,
                "risk_score": risk.score,
                "evidence_count": len(evidence_items),
                "evidence_categories": categories,
                "evidence": evidence_items,
                "why_flagged": self._why_flagged(risk.score, evidence_items),
                "mitre_mappings": [f"{item.tactic}: {item.technique_id} {item.name}" for item in techniques],
            },
        )

    def _why_flagged(self, score: int, evidence_items: list[dict]) -> str:
        if not evidence_items:
            return "No detection evidence was present."
        categories = [str(item.get("category") or item.get("title") or "evidence") for item in evidence_items]
        if score <= 10:
            return f"Informational only: {', '.join(categories)} did not meet suspicious-risk threshold."
        return f"Score {score} from evidence: {', '.join(categories)}."
