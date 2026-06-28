from __future__ import annotations

from edr_engine.ai_analyst.formatter import format_markdown
from edr_engine.ai_analyst.models import (
    AnalystAlert,
    AnalystIncident,
    AnalystInput,
    MitreMapping,
    ThreatIntelMatch,
)
from edr_engine.ai_analyst.service import AISecurityAnalyst


def build_sample_context() -> AnalystInput:
    return AnalystInput(
        subject="Finance workstation investigation",
        risk_score=82,
        alerts=[
            AnalystAlert(
                alert_id="ALT-1001",
                title="PowerShell spawned from Office",
                severity="high",
                device_id="FIN-WKS-014",
                risk_score=82,
            ),
            AnalystAlert(
                alert_id="ALT-1002",
                title="Unusual DNS query length",
                severity="medium",
                device_id="FIN-WKS-014",
                risk_score=58,
            ),
        ],
        incidents=[
            AnalystIncident(
                incident_id="INC-1001",
                title="Unknown device with suspicious DNS and beaconing",
                severity="high",
                risk_score=91,
                affected_device="FIN-WKS-014",
                timeline=[
                    {"time": "2026-06-18T02:00:00Z", "event": "Unknown device alert"},
                    {"time": "2026-06-18T02:01:00Z", "event": "Suspicious DNS query"},
                    {"time": "2026-06-18T02:02:00Z", "event": "Beaconing pattern"},
                ],
                evidence=[
                    "Unknown endpoint observed",
                    "DNS query uses high-risk TLD",
                    "Regular outbound intervals observed",
                ],
                related_alert_ids=["ALT-1001", "ALT-1002"],
            )
        ],
        mitre_mappings=[
            MitreMapping("T1059", "Command and Scripting Interpreter", "Execution", "high"),
            MitreMapping("T1071.004", "DNS", "Command and Control", "medium"),
        ],
        threat_intel_matches=[
            ThreatIntelMatch("xj92ksla88qqw7z19pqq.example.xyz", "domain", "local-ti", "suspicious"),
        ],
    )


def main() -> int:
    report = AISecurityAnalyst().generate(build_sample_context())
    print(format_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
