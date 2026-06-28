from __future__ import annotations

import json

from .db import fetch_all


def _rows(table: str, limit: int = 25, session_id: str | None = None):
    if session_id:
        return fetch_all(f"SELECT * FROM {table} WHERE session_id = ? ORDER BY id DESC LIMIT ?", (session_id, limit))
    return fetch_all(f"SELECT * FROM {table} WHERE 1 = 0 ORDER BY id DESC LIMIT ?", (limit,))


def generate_analysis(session_id: str | None = None) -> str:
    if session_id is None:
        from .sessions import get_current_session_id

        session_id = get_current_session_id()
    alerts = _rows("alerts", 20, session_id)
    incidents = _rows("incidents", 10, session_id)
    validations = _rows("validation_results", 100, session_id)
    metrics = _rows("performance_metrics", 20, session_id)
    scan_results = _rows("scan_results", 10, session_id)
    failed_attempts = _rows("failed_attempts", 10, session_id)
    cves = _rows("cve_matches", 10, session_id)

    high_alerts = [row for row in alerts if row["classification"] in {"HIGH RISK", "CONFIRMED THREAT"}]
    confirmed_alerts = [row for row in alerts if row["classification"] == "CONFIRMED THREAT"]
    outcomes = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for row in validations:
        outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1

    total_validations = sum(outcomes.values())
    accuracy = ((outcomes["TP"] + outcomes["TN"]) / total_validations) if total_validations else 0

    lines = [
        "AI Security Analyst Report",
        "",
        "Executive Summary",
        f"- Current evidence contains {len(alerts)} recent alerts and {len(incidents)} recent incidents.",
        f"- Recent endpoint scan records: {len(scan_results)}. Recent failed-attempt records: {len(failed_attempts)}. Recent CVE matches: {len(cves)}.",
        f"- High-risk or confirmed alert count in the current window: {len(high_alerts)}.",
        f"- Confirmed findings backed by IoC evidence: {len(confirmed_alerts)}.",
        f"- Validation accuracy from recorded tests: {accuracy:.2%}." if total_validations else "- No validation runs are recorded yet.",
        "",
        "Evidence Overview",
    ]

    if not alerts:
        lines.append("- No alerts are currently recorded.")
    else:
        for row in alerts[:8]:
            evidence = json.loads(row["evidence"])
            lines.append(
                f"- {row['classification']} ({row['confidence_score']}% confidence): "
                f"{row['alert_type']} on {row['entity']} with {row['evidence_count']} evidence item(s). {row['reason']}"
            )
            if evidence:
                lines.append(f"  Evidence: {json.dumps(evidence, sort_keys=True)}")

    lines.extend(["", "Key Findings"])
    if incidents:
        for row in incidents[:5]:
            lines.append(f"- {row['title']} with score {row['score']} and status {row['status']}.")
    else:
        lines.append("- No multi-alert incidents have been correlated yet.")
    if failed_attempts:
        lines.append(f"- Authentication risk is present: {len(failed_attempts)} failed-attempt clusters are recorded.")
    if cves:
        lines.append(f"- Vulnerability risk is present: {len(cves)} CVE matches are recorded.")

    lines.extend(["", "Risk Assessment"])
    if confirmed_alerts:
        lines.append("- Confirmed malicious IoC evidence is present; immediate analyst review is recommended.")
    elif high_alerts:
        lines.append("- High-risk correlated evidence is present, but no compromise is asserted without confirmation.")
    else:
        lines.append("- Current recorded risk is below the high-risk threshold.")

    lines.extend(["", "Validation"])
    if total_validations:
        lines.append(f"- TP={outcomes['TP']} TN={outcomes['TN']} FP={outcomes['FP']} FN={outcomes['FN']}.")
    else:
        lines.append("- Run the validation simulator to produce TP/TN/FP/FN metrics.")

    lines.extend(["", "Performance"])
    detection_metrics = [row for row in metrics if row["metric_name"] == "detection_time"]
    if detection_metrics:
        avg = sum(float(row["metric_value"]) for row in detection_metrics) / len(detection_metrics)
        lines.append(f"- Average recorded detection time in recent samples: {avg:.2f} ms.")
    else:
        lines.append("- No detection-time metrics are recorded yet.")

    lines.extend(["", "Recommendations"])
    if high_alerts:
        lines.append("- Prioritize entities with correlated incidents, malicious indicators, or critical CVEs.")
        lines.append("- Validate endpoint owner, isolate only when evidence confirms malicious behavior, then collect process and network artifacts.")
    else:
        lines.append("- Continue monitoring, refresh threat intelligence, and run validation before a demonstration.")

    verdict = "CONFIRMED THREAT: malicious IoC evidence found." if confirmed_alerts else "SAFE: no confirmed threat found in recorded evidence."
    lines.extend(["", "Conclusion", f"- {verdict}", "- This analysis only uses recorded evidence. It does not call an item a threat without confirmation."])
    return "\n".join(lines)
