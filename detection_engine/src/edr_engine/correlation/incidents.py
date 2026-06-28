from __future__ import annotations

import hashlib
from dataclasses import dataclass


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SUSPICIOUS_DNS_CATEGORIES = {
    "suspicious_dns",
    "dns_length_anomaly",
    "dns_tld_reputation",
    "possible_dga",
    "dns_transport",
}


@dataclass(frozen=True)
class AlertCorrelationRecord:
    alert_id: str
    device_id: str
    title: str
    description: str
    severity: str
    risk_score: int
    created_at_utc: str
    category: str


@dataclass(frozen=True)
class CorrelatedIncident:
    incident_id: str
    title: str
    summary: str
    severity: str
    risk_score: int
    device_id: str
    alert_ids: list[str]
    timeline: list[dict[str, str]]
    evidence: list[str]
    categories: list[str]
    correlation_rule: str
    opened_at_utc: str
    updated_at_utc: str


class IncidentCorrelationEngine:
    def correlate(self, device_id: str, alerts: list[AlertCorrelationRecord]) -> list[CorrelatedIncident]:
        if not alerts:
            return []

        unknown_device = [alert for alert in alerts if alert.category == "asset_inventory"]
        suspicious_dns = [alert for alert in alerts if alert.category in SUSPICIOUS_DNS_CATEGORIES]
        beaconing = [alert for alert in alerts if alert.category == "beaconing"]
        if not (unknown_device and suspicious_dns and beaconing):
            return []

        related = self._dedupe_alerts([*unknown_device, *suspicious_dns, *beaconing])
        related.sort(key=lambda alert: alert.created_at_utc)
        risk_score = min(100, max(alert.risk_score for alert in related) + 15)
        incident_id = self._incident_id(device_id, "unknown_dns_beaconing")
        first_seen = related[0].created_at_utc
        last_seen = related[-1].created_at_utc
        categories = sorted({alert.category for alert in related})

        return [
            CorrelatedIncident(
                incident_id=incident_id,
                title=f"High-risk unknown device with DNS and beaconing activity on {device_id}",
                summary=(
                    "Unknown device activity correlated with suspicious DNS and beaconing behavior. "
                    "Treat as a high-risk incident requiring triage."
                ),
                severity="high",
                risk_score=risk_score,
                device_id=device_id,
                alert_ids=[alert.alert_id for alert in related],
                timeline=[
                    {
                        "time": alert.created_at_utc,
                        "alert_id": alert.alert_id,
                        "event": alert.title,
                        "category": alert.category,
                    }
                    for alert in related
                ],
                evidence=[
                    f"{alert.created_at_utc}: {alert.title} - {alert.description}"
                    for alert in related
                ],
                categories=categories,
                correlation_rule="unknown_device+suspicious_dns+beaconing",
                opened_at_utc=first_seen,
                updated_at_utc=last_seen,
            )
        ]

    def _incident_id(self, device_id: str, rule: str) -> str:
        digest = hashlib.sha1(f"{device_id}:{rule}".encode("utf-8")).hexdigest()[:12].upper()
        return f"INC-{digest}"

    def _dedupe_alerts(self, alerts: list[AlertCorrelationRecord]) -> list[AlertCorrelationRecord]:
        seen = set()
        unique = []
        for alert in alerts:
            if alert.alert_id in seen:
                continue
            seen.add(alert.alert_id)
            unique.append(alert)
        return unique
