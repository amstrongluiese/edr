from __future__ import annotations

import json

from .db import fetch_all


def _rows(table: str, limit: int = 25):
    return fetch_all(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,))


def generate_analysis() -> str:
    alerts = _rows("alerts", 20)
    incidents = _rows("incidents", 10)
    validations = _rows("validation_results", 20)
    metrics = _rows("performance_metrics", 20)
    scan_results = _rows("scan_results", 10)
    failed_attempts = _rows("failed_attempts", 10)
    cves = _rows("cve_matches", 10)

    high_alerts = [row for row in alerts if row["severity"] in {"High Risk", "Critical"}]
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
        f"- High or critical alert count in the current window: {len(high_alerts)}.",
        f"- Validation accuracy from recorded tests: {accuracy:.2%}." if total_validations else "- No validation runs are recorded yet.",
        "",
        "Threat Overview",
    ]

    if not alerts:
        lines.append("- No alerts are currently recorded.")
    else:
        for row in alerts[:8]:
            evidence = json.loads(row["evidence"])
            lines.append(f"- {row['severity']}: {row['alert_type']} on {row['entity']} scored {row['score']} because {row['reason']}")
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
    if high_alerts:
        lines.append("- Immediate review is recommended for high and critical alerts with malicious IoC, beaconing, or CVE evidence.")
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

    lines.extend(["", "Conclusion", "- This analysis only uses recorded alerts, incidents, validation data, and performance metrics. No unobserved compromise is asserted."])
    return "\n".join(lines)
