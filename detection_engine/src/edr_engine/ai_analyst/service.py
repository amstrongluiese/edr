from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from edr_engine.ai_analyst.models import AnalystInput, AnalystReport
from edr_engine.ai_analyst.providers import AnalystLLMProvider


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class AISecurityAnalyst:
    """Produces analyst-ready narrative sections from structured EDR context."""

    def __init__(self, provider: AnalystLLMProvider | None = None, allow_fallback: bool = True) -> None:
        self.provider = provider
        self.allow_fallback = allow_fallback

    def generate(self, context: AnalystInput) -> AnalystReport:
        if self.provider is not None:
            try:
                report = self.provider.generate(context)
                return AnalystReport(
                    executive_summary=report.executive_summary,
                    technical_findings=report.technical_findings,
                    recommendations=report.recommendations,
                    incident_narrative=report.incident_narrative,
                    metadata={**report.metadata, "fallback_used": False},
                )
            except Exception as exc:
                if not self.allow_fallback:
                    raise
                fallback = self._generate_deterministic(context)
                return AnalystReport(
                    executive_summary=fallback.executive_summary,
                    technical_findings=fallback.technical_findings,
                    recommendations=fallback.recommendations,
                    incident_narrative=fallback.incident_narrative,
                    metadata={**fallback.metadata, "fallback_used": True, "provider_error": str(exc)},
                )
        return self._generate_deterministic(context)

    def _generate_deterministic(self, context: AnalystInput) -> AnalystReport:
        normalized_score = max(0, min(100, context.risk_score))
        generated_at = context.generated_at_utc or datetime.now(timezone.utc)
        severity_counts = Counter(alert.severity.lower() for alert in context.alerts)
        top_severity = self._top_severity(severity_counts)
        tactics = Counter(mapping.tactic for mapping in context.mitre_mappings)
        intel_reputations = Counter(match.reputation.lower() for match in context.threat_intel_matches)

        return AnalystReport(
            executive_summary=self._executive_summary(
                context,
                normalized_score,
                top_severity,
                severity_counts,
                intel_reputations,
            ),
            technical_findings=self._technical_findings(context, tactics, intel_reputations),
            recommendations=self._recommendations(context, normalized_score, top_severity, intel_reputations),
            incident_narrative=self._incident_narrative(context),
            metadata={
                "subject": context.subject,
                "risk_score": normalized_score,
                "alert_count": len(context.alerts),
                "incident_count": len(context.incidents),
                "mitre_mapping_count": len(context.mitre_mappings),
                "threat_intel_match_count": len(context.threat_intel_matches),
                "generated_at_utc": generated_at.isoformat().replace("+00:00", "Z"),
                "provider": "deterministic",
            },
        )

    def _executive_summary(
        self,
        context: AnalystInput,
        risk_score: int,
        top_severity: str,
        severity_counts: Counter,
        intel_reputations: Counter,
    ) -> str:
        alert_phrase = f"{len(context.alerts)} alert" + ("" if len(context.alerts) == 1 else "s")
        intel_phrase = f"{len(context.threat_intel_matches)} threat intelligence match"
        if len(context.threat_intel_matches) != 1:
            intel_phrase += "es"

        if risk_score >= 70 or top_severity in {"high", "critical"}:
            posture = "elevated security risk requiring analyst attention"
        elif risk_score >= 40 or top_severity == "medium":
            posture = "moderate security risk requiring triage"
        else:
            posture = "low immediate risk with continued monitoring recommended"

        severe_total = severity_counts["critical"] + severity_counts["high"]
        intel_total = intel_reputations["malicious"] + intel_reputations["suspicious"]

        return (
            f"{context.subject} currently shows {posture}. "
            f"The aggregate risk score is {risk_score}/100 with {alert_phrase}, "
            f"including {severe_total} high-priority alert(s). "
            f"The context includes {intel_phrase}, with {intel_total} suspicious or malicious match(es)."
        )

    def _technical_findings(
        self,
        context: AnalystInput,
        tactics: Counter,
        intel_reputations: Counter,
    ) -> str:
        alert_lines = [
            f"- {alert.severity.upper()}: {alert.title} on {alert.device_id} (risk {alert.risk_score}/100)"
            for alert in context.alerts
        ] or ["- No alerts were provided."]

        incident_lines = [
            f"- {incident.severity.upper()}: {self._incident_title_with_device(incident.title, incident.affected_device)} "
            f"(risk {incident.risk_score}/100, status: {incident.status})"
            for incident in context.incidents
        ] or ["- No incidents were provided."]

        mitre_lines = [
            f"- {mapping.technique_id} {mapping.technique_name} ({mapping.tactic}, confidence: {mapping.confidence})"
            for mapping in context.mitre_mappings
        ] or ["- No MITRE mappings were provided."]

        intel_lines = [
            f"- {match.observable_type}:{match.observable} from {match.source} is {match.reputation}"
            for match in context.threat_intel_matches
        ] or ["- No threat intelligence matches were provided."]

        dominant_tactic = tactics.most_common(1)[0][0] if tactics else "none"
        dominant_intel = intel_reputations.most_common(1)[0][0] if intel_reputations else "none"

        return "\n".join(
            [
                f"Dominant MITRE tactic: {dominant_tactic}.",
                f"Dominant threat intelligence reputation: {dominant_intel}.",
                "",
                "Alerts:",
                *alert_lines,
                "",
                "Incidents:",
                *incident_lines,
                "",
                "MITRE ATT&CK mappings:",
                *mitre_lines,
                "",
                "Threat intelligence matches:",
                *intel_lines,
            ]
        )

    def _incident_narrative(self, context: AnalystInput) -> str:
        if not context.incidents:
            return "No correlated incidents are currently recorded. Continue monitoring for alert combinations that indicate a broader attack sequence."

        narratives = []
        for incident in context.incidents:
            timeline = " -> ".join(
                f"{item.get('time', 'unknown time')}: {item.get('event', item.get('category', 'activity'))}"
                for item in incident.timeline
            )
            evidence = "; ".join(incident.evidence) if incident.evidence else "No detailed evidence attached."
            narratives.append(
                f"{incident.incident_id} is a {incident.severity} incident affecting {incident.affected_device} "
                f"with risk score {incident.risk_score}/100. Timeline: {timeline or 'No timeline available'}. "
                f"Evidence: {evidence}"
            )
        return "\n\n".join(narratives)

    def _recommendations(
        self,
        context: AnalystInput,
        risk_score: int,
        top_severity: str,
        intel_reputations: Counter,
    ) -> list[str]:
        recommendations: list[str] = []

        if risk_score >= 70 or top_severity in {"high", "critical"}:
            recommendations.append("Prioritize triage of high-severity alerts and confirm endpoint containment status.")
        elif context.alerts:
            recommendations.append("Review medium and low severity alerts for common devices, users, and time windows.")
        else:
            recommendations.append("Continue monitoring and maintain baseline telemetry collection.")

        if intel_reputations["malicious"] or intel_reputations["suspicious"]:
            recommendations.append("Validate suspicious observables against threat intelligence sources and block confirmed indicators.")

        if context.mitre_mappings:
            recommendations.append("Use the mapped MITRE techniques to guide investigation notes and control coverage review.")

        affected_devices = sorted({alert.device_id for alert in context.alerts})
        affected_devices.extend(
            device for device in sorted({incident.affected_device for incident in context.incidents}) if device not in affected_devices
        )
        if len(affected_devices) > 1:
            recommendations.append("Correlate activity across affected devices to determine whether this is a campaign or isolated events.")

        if context.incidents:
            recommendations.append("Review correlated incident timelines and validate each linked alert before containment or closure.")

        recommendations.append("Document analyst disposition and preserve supporting event evidence for reporting.")
        return recommendations

    def _incident_title_with_device(self, title: str, device: str) -> str:
        if device and device.lower() not in title.lower():
            return f"{title} on {device}"
        return title

    def _top_severity(self, severity_counts: Counter) -> str:
        if not severity_counts:
            return "info"
        return max(severity_counts, key=lambda severity: SEVERITY_RANK.get(severity, 0))
