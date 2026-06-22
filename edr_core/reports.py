from __future__ import annotations

from pathlib import Path

from .ai_analyst import generate_analysis
from .config import REPORT_DIR
from .db import execute, fetch_all, init_db, utc_now
from .detection import summarize_counts
from .sessions import get_current_session_id


def _write_report(name: str, content: str) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / name
    path.write_text(content, encoding="utf-8")
    execute(
        "INSERT INTO reports(created_at, report_type, path, summary, session_id) VALUES (?, ?, ?, ?, ?)",
        (utc_now(), name.replace(".md", ""), str(path), content.splitlines()[0] if content else "Report", get_current_session_id()),
    )
    return path


def technical_report() -> Path:
    session_id = get_current_session_id()
    counts = summarize_counts(session_id)
    alerts = fetch_all("SELECT * FROM alerts WHERE session_id = ? ORDER BY id DESC LIMIT 20", (session_id,)) if session_id else []
    lines = [
        "# Technical EDR Report",
        "",
        "## What happened?",
        f"The system recorded {counts['devices']} devices, {counts['connections']} connections, {counts['dns_logs']} DNS events, {counts['file_events']} file events, {counts['process_events']} process events, {counts['log_events']} log events, {counts['alerts']} alerts, and {counts['incidents']} incidents.",
        "",
        "## Why flagged?",
    ]
    if alerts:
        for row in alerts:
            lines.append(f"- Alert {row['id']}: {row['alert_type']} on {row['entity']} scored {row['score']} ({row['severity']}). Reason: {row['reason']}")
    else:
        lines.append("- No alerts have been generated.")
    lines.extend(["", "## Severity", "Severity is derived from weighted, capped scores: informational, low risk, suspicious, high risk, and critical."])
    return _write_report("technical_report.md", "\n".join(lines))


def validation_report() -> Path:
    session_id = get_current_session_id()
    latest = fetch_all("SELECT validation_run_id FROM validation_results WHERE validation_run_id IS NOT NULL AND session_id = ? ORDER BY id DESC LIMIT 1", (session_id,)) if session_id else []
    if latest:
        rows = fetch_all("SELECT * FROM validation_results WHERE validation_run_id = ? AND session_id = ? ORDER BY id DESC", (latest[0]["validation_run_id"], session_id))
    else:
        rows = []
    outcomes = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for row in rows:
        outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1
    total = sum(outcomes.values())
    accuracy = ((outcomes["TP"] + outcomes["TN"]) / total) if total else 0
    fpr = outcomes["FP"] / (outcomes["FP"] + outcomes["TN"]) if (outcomes["FP"] + outcomes["TN"]) else 0
    fnr = outcomes["FN"] / (outcomes["FN"] + outcomes["TP"]) if (outcomes["FN"] + outcomes["TP"]) else 0
    lines = [
        "# Validation Report",
        "",
        "## Was detection correct?",
        f"Accuracy: {accuracy:.2%}",
        f"False Positive Rate: {fpr:.2%}",
        f"False Negative Rate: {fnr:.2%}",
        f"TP={outcomes['TP']} TN={outcomes['TN']} FP={outcomes['FP']} FN={outcomes['FN']}",
        "",
        "## Test Results",
    ]
    for row in rows:
        lines.append(f"- {row['test_name']}: {row['outcome']} in {row['response_ms']:.2f} ms. Notes: {row['notes']}")
    return _write_report("validation_report.md", "\n".join(lines))


def ai_report() -> Path:
    return _write_report("ai_security_analysis_report.md", generate_analysis())


def final_overall_report() -> Path:
    session_id = get_current_session_id()
    counts = summarize_counts(session_id)
    latest = fetch_all("SELECT validation_run_id FROM validation_results WHERE validation_run_id IS NOT NULL AND session_id = ? ORDER BY id DESC LIMIT 1", (session_id,)) if session_id else []
    if latest:
        validations = fetch_all("SELECT * FROM validation_results WHERE validation_run_id = ? AND session_id = ? ORDER BY id DESC", (latest[0]["validation_run_id"], session_id))
    else:
        validations = []
    metrics = fetch_all("SELECT * FROM performance_metrics WHERE session_id = ? ORDER BY id DESC LIMIT 30", (session_id,)) if session_id else []
    verification = fetch_all("SELECT * FROM testing_verification WHERE session_id = ? ORDER BY id DESC", (session_id,)) if session_id else []
    outcomes = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for row in validations:
        outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1
    total = sum(outcomes.values())
    accuracy = ((outcomes["TP"] + outcomes["TN"]) / total) if total else 0
    fpr = outcomes["FP"] / (outcomes["FP"] + outcomes["TN"]) if (outcomes["FP"] + outcomes["TN"]) else 0
    fnr = outcomes["FN"] / (outcomes["FN"] + outcomes["TP"]) if (outcomes["FN"] + outcomes["TP"]) else 0
    detection_times = [float(row["metric_value"]) for row in metrics if row["metric_name"] == "detection_time"]
    avg_detection = sum(detection_times) / len(detection_times) if detection_times else 0
    lines = [
        "# Final Overall Security Report",
        "",
        "## What was scanned?",
        f"Devices={counts['devices']}, scan records={counts['scan_results']}, files={counts['file_events']}, processes={counts['process_events']}, connections={counts['connections']}, DNS={counts['dns_logs']}, logs={counts['log_events']}.",
        "",
        "## What was detected?",
        f"Alerts={counts['alerts']}, incidents={counts['incidents']}, failed-attempt clusters={counts['failed_attempts']}, CVE matches={counts['cve_matches']}.",
        "",
        "## Was it a true detection?",
        f"Validation TP={outcomes['TP']} TN={outcomes['TN']} FP={outcomes['FP']} FN={outcomes['FN']}.",
        f"Testing verification records={len(verification)}.",
        "",
        "## Why was it flagged?",
        "Each alert stores evidence JSON, score, reason, data source, and MITRE mapping in SQLite.",
        "",
        "## How severe was it?",
        "Severity follows weighted evidence-based risk scoring. Unknown device alone remains informational.",
        "",
        "## How accurate is the system?",
        f"Detection accuracy={accuracy:.2%}; false positive rate={fpr:.2%}; false negative rate={fnr:.2%}; average detection time={avg_detection:.2f} ms.",
        "",
        "## What should be done?",
        generate_analysis(),
    ]
    return _write_report("final_overall_security_report.md", "\n".join(lines))


def generate_all_reports() -> list[Path]:
    init_db()
    return [technical_report(), validation_report(), ai_report(), final_overall_report()]


def main() -> None:
    for path in generate_all_reports():
        print(path)


if __name__ == "__main__":
    main()
