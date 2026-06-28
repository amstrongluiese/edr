from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from edr_engine.core.events import DetectionFinding, RiskAssessment, SensorEvent


SEVERITY_POINTS = {
    "info": 5,
    "low": 15,
    "medium": 30,
    "high": 60,
    "critical": 85,
}


def severity_from_score(score: int) -> str:
    if score >= 81:
        return "critical"
    if score >= 61:
        return "high"
    if score >= 31:
        return "medium"
    if score >= 11:
        return "low"
    return "info"


def risk_level_from_score(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High Risk"
    if score >= 31:
        return "Suspicious"
    if score >= 11:
        return "Low Risk"
    return "Informational"


class RiskScorer:
    def score(self, event: SensorEvent, findings: list[DetectionFinding]) -> RiskAssessment:
        score = 0
        reasons: list[str] = []

        for finding in findings:
            points = self._finding_points(finding)
            score += points
            evidence = finding.metadata.get("basis") or finding.title
            reasons.append(f"+{points} {finding.provider_id}: {evidence}")

        score = min(score, 100)

        return RiskAssessment(
            risk_id=str(uuid4()),
            event_id=event.event_id,
            asset_id=event.asset_id,
            score=score,
            severity=severity_from_score(score),
            reasons=reasons,
            created_at_utc=datetime.now(timezone.utc),
        )

    def _finding_points(self, finding: DetectionFinding) -> int:
        explicit = finding.metadata.get("risk_points")
        try:
            if explicit is not None:
                return int(explicit)
        except (TypeError, ValueError):
            pass

        category_points = {
            "asset_inventory": 5,
            "new_device_first_seen": 5,
            "risky_open_port": 15,
            "smb_rdp_access": 15,
            "repeated_connection": 20,
            "dns_length_anomaly": 25,
            "dns_tld_reputation": 25,
            "possible_dga": 25,
            "dns_transport": 25,
            "beaconing": 30,
            "port_discovery": 30,
            "large_data_transfer": 20,
            "threat_intel_ip": 40,
            "threat_intel_domain": 40,
            "threat_intel_url": 40,
            "threat_intel_hash": 50,
            "threat_intel_cve": 20,
        }
        category = str(finding.metadata.get("category", ""))
        if category in category_points:
            return category_points[category]

        cve_severity = str(finding.metadata.get("cve_severity", "")).lower()
        cve_points = {"critical": 50, "high": 35, "medium": 20, "low": 10}
        if cve_severity in cve_points:
            return cve_points[cve_severity]

        return SEVERITY_POINTS.get(finding.severity.lower(), 10)
