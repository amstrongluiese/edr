from __future__ import annotations

from edr_engine.ai_analyst.models import AnalystReport


def format_markdown(report: AnalystReport) -> str:
    recommendations = "\n".join(f"- {item}" for item in report.recommendations)
    return "\n".join(
        [
            "# AI Security Analyst Report",
            "",
            "## Executive Summary",
            "",
            report.executive_summary,
            "",
            "## Technical Findings",
            "",
            report.technical_findings,
            "",
            "## Incident Narrative",
            "",
            report.incident_narrative,
            "",
            "## Recommendations",
            "",
            recommendations,
        ]
    )
