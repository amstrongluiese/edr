from __future__ import annotations

import json
import os
import sqlite3
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from edr_dashboard.device_discovery import DEFAULT_DB_PATH, PROJECT_ROOT


REPORT_DIR = PROJECT_ROOT / "reports" / "ai_analysis"


@dataclass(frozen=True)
class AIAnalystSettings:
    mode: str = "Offline"
    model_name: str = ""
    api_base_url: str = ""
    api_key: str = ""
    max_items: int = 150


@dataclass(frozen=True)
class AIReport:
    executive_summary: str
    threat_overview: dict[str, Any]
    key_findings: list[str]
    affected_devices: list[str]
    risk_assessment: str
    mitre_attack_summary: list[str]
    timeline_summary: list[str]
    validation_summary: str
    recommended_actions: list[str]
    conclusion: str
    generated_at: str
    mode_used: str
    source_counts: dict[str, int] = field(default_factory=dict)

    def to_text(self) -> str:
        lines = [
            "AI SECURITY ANALYSIS REPORT",
            "",
            f"Generated At: {self.generated_at}",
            f"AI Mode Used: {self.mode_used}",
            "",
            "Executive Summary:",
            self.executive_summary,
            "",
            "Threat Overview:",
        ]
        lines.extend(f"- {key}: {value}" for key, value in self.threat_overview.items())
        lines.extend(["", "Key Findings:"])
        lines.extend(f"{index}. {item}" for index, item in enumerate(self.key_findings, start=1))
        lines.extend(["", "Affected Devices:"])
        lines.extend(f"- {item}" for item in self.affected_devices)
        lines.extend(["", "Risk Assessment:", self.risk_assessment, "", "MITRE ATT&CK Summary:"])
        lines.extend(f"- {item}" for item in self.mitre_attack_summary)
        lines.extend(["", "Timeline Summary:"])
        lines.extend(f"- {item}" for item in self.timeline_summary)
        lines.extend(["", "Validation Summary:", self.validation_summary, "", "Recommended Actions:"])
        lines.extend(f"{index}. {item}" for index, item in enumerate(self.recommended_actions, start=1))
        lines.extend(["", "Conclusion:", self.conclusion])
        return "\n".join(lines)


class AIReportIntelligence:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH, report_dir: Path = REPORT_DIR) -> None:
        self.db_path = db_path
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_validation_schema()

    def generate_ai_security_summary(self, settings: AIAnalystSettings | None = None, scope: str = "all") -> AIReport:
        settings = settings or AIAnalystSettings()
        data = self.collect_data(settings.max_items, scope)
        if self._is_empty(data):
            return self._empty_report(settings.mode)

        offline_report = self._offline_summary(data, settings.mode)
        if settings.mode.lower() == "offline":
            return offline_report

        llm_text = self._try_llm_summary(data, settings)
        if not llm_text:
            return offline_report
        return self._report_from_llm_text(offline_report, llm_text, settings.mode)

    def collect_data(self, max_items: int = 150, scope: str = "all") -> dict[str, Any]:
        with self._connect() as conn:
            data = {
                "alerts": self._rows(conn, "alerts", "created_at_utc", max_items),
                "incidents": self._rows(conn, "incidents", "updated_at_utc", max_items),
                "devices": self._rows(conn, "devices", "last_seen_utc", max_items),
                "connections": self._connection_rows(conn, max_items),
                "dns_logs": self._dns_rows(conn, max_items),
                "traffic_logs": self._traffic_rows(conn, max_items),
                "validation_results": self._rows(conn, "validation_results", "created_at_utc", max_items),
                "validation_metrics": self._rows(conn, "validation_metrics", "created_at_utc", max_items),
                "mitre_mappings": self._rows(conn, "mitre_mappings", "created_at_utc", max_items),
                "reports": self._report_rows(conn, max_items),
            }
        data["report_files"] = self._report_files(max_items)
        if scope == "incidents":
            data["alerts"] = self._alerts_linked_to_incidents(data["alerts"], data["incidents"])
            data["connections"] = []
            data["dns_logs"] = []
            data["traffic_logs"] = []
        if scope == "validation":
            return {
                "validation_results": data["validation_results"],
                "validation_metrics": data["validation_metrics"],
                "mitre_mappings": data["mitre_mappings"],
            }
        if scope == "reports":
            return {"reports": data["reports"], "report_files": data["report_files"], "mitre_mappings": data["mitre_mappings"]}
        return data

    def save_report(self, report: AIReport) -> dict[str, str]:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = self.report_dir / f"ai-security-analysis-{timestamp}"
        txt_path = base.with_suffix(".txt")
        json_path = base.with_suffix(".json")
        txt_path.write_text(report.to_text(), encoding="utf-8")
        json_path.write_text(json.dumps(asdict(report), indent=2, sort_keys=True), encoding="utf-8")
        outputs = {"txt": str(txt_path), "json": str(json_path)}

        docx_path = self._try_write_docx(base.with_suffix(".docx"), report)
        if docx_path:
            outputs["docx"] = str(docx_path)
        pdf_path = self._try_write_pdf(base.with_suffix(".pdf"), report)
        if pdf_path:
            outputs["pdf"] = str(pdf_path)

        self._store_report_artifact(report, outputs)
        return outputs

    def save_validation_result(self, result: dict) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        with self._connect() as conn:
            result_id = str(uuid4())
            conn.execute(
                """
                INSERT INTO validation_results (
                    result_id, test_name, expected_result, actual_result, pass_fail, evidence, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result_id,
                    result.get("test", ""),
                    result.get("expected_result", ""),
                    result.get("actual_result", ""),
                    result.get("pass_fail", ""),
                    result.get("evidence", ""),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO validation_metrics (
                    metric_id,
                    result_id,
                    test_name,
                    expected_positive,
                    detected_positive,
                    true_positive,
                    true_negative,
                    false_positive,
                    false_negative,
                    response_time_ms,
                    cpu_usage_percent,
                    memory_usage_mb,
                    ioc_matches,
                    cve_matches,
                    created_at_utc,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    result_id,
                    result.get("test", ""),
                    int(bool(result.get("expected_positive"))),
                    int(bool(result.get("detected_positive"))),
                    int(result.get("true_positive") or 0),
                    int(result.get("true_negative") or 0),
                    int(result.get("false_positive") or 0),
                    int(result.get("false_negative") or 0),
                    int(result.get("response_time_ms") or 0),
                    float(result.get("cpu_usage_percent") or 0),
                    float(result.get("memory_usage_mb") or 0),
                    int(result.get("ioc_matches") or 0),
                    int(result.get("cve_matches") or 0),
                    now,
                    json.dumps(result, sort_keys=True),
                ),
            )

    def _offline_summary(self, data: dict[str, Any], mode: str) -> AIReport:
        alerts = data.get("alerts", [])
        incidents = data.get("incidents", [])
        devices = data.get("devices", [])
        validations = data.get("validation_results", [])
        validation_metrics = data.get("validation_metrics", [])
        mitre = data.get("mitre_mappings", [])
        dns_logs = data.get("dns_logs", [])
        traffic_logs = data.get("traffic_logs", [])
        connections = data.get("connections", [])
        report_files = data.get("report_files", [])

        highest_risk = max([int(row.get("risk_score") or 0) for row in alerts + incidents], default=0)
        unknown_devices = sum(1 for row in devices if str(row.get("status", "")).lower() == "unknown")
        alert_types = Counter(str(row.get("title") or row.get("provider_id") or "Unknown") for row in alerts)
        affected = Counter(str(row.get("device_id") or row.get("owner") or row.get("hostname") or "Unknown") for row in alerts + incidents)
        tactics = Counter(str(row.get("tactic") or "Unknown") for row in mitre)
        pass_count = sum(1 for row in validations if row.get("pass_fail") == "PASS")
        fail_count = sum(1 for row in validations if row.get("pass_fail") == "FAIL")
        tp = sum(int(row.get("true_positive") or 0) for row in validation_metrics)
        tn = sum(int(row.get("true_negative") or 0) for row in validation_metrics)
        fp = sum(int(row.get("false_positive") or 0) for row in validation_metrics)
        fn = sum(int(row.get("false_negative") or 0) for row in validation_metrics)

        if not alerts and not incidents and not connections and not dns_logs and not traffic_logs:
            return self._empty_report(mode)

        common_alert = alert_types.most_common(1)[0][0] if alert_types else "No alert type observed"
        most_affected = affected.most_common(1)[0][0] if affected else "No affected device identified"
        tactic_summary = [f"{row.get('technique_id')} {row.get('technique_name')} ({row.get('tactic')})" for row in mitre[:10]]

        key_findings = [
            f"{len(alerts)} alert(s) were available for analysis.",
            f"The highest observed risk score was {highest_risk}.",
            f"The most common alert type was: {common_alert}.",
            f"The most affected device was: {most_affected}.",
        ]
        if validation_metrics:
            tested = tp + tn + fp + fn
            accuracy = round(((tp + tn) / tested) * 100, 1) if tested else 0
            key_findings.append(f"Validation accuracy is {accuracy}% across {tested} labeled metric record(s).")
        if dns_logs:
            key_findings.append(f"{len(dns_logs)} DNS telemetry record(s) were available.")
        if traffic_logs:
            key_findings.append(f"{len(traffic_logs)} traffic telemetry record(s) were available.")
        if report_files:
            key_findings.append(f"{len(report_files)} generated report file(s) were reviewed.")

        recommendations = [
            "Review high-risk alerts and verify whether affected devices require containment.",
            "Validate unknown devices against the trusted inventory.",
            "Investigate suspicious DNS events and repeated outbound connection patterns.",
            "Export incident evidence for documentation and thesis/demo review.",
        ]
        if fail_count:
            recommendations.append("Review failed validation tests and confirm the relevant detection rules are enabled.")

        generated_at = datetime.now().isoformat(timespec="seconds")
        return AIReport(
            executive_summary=(
                f"The system monitored {len(devices)} device record(s) and recorded {len(alerts)} alert(s). "
                f"The highest observed risk score was {highest_risk}, with {len(incidents)} open or stored incident(s)."
            ),
            threat_overview={
                "Total Alerts": len(alerts),
                "Open Incidents": sum(1 for row in incidents if str(row.get("status", "")).lower() == "open"),
                "Unknown Devices": unknown_devices,
                "Suspicious DNS Events": len(dns_logs),
                "Highest Risk Score": highest_risk,
                "Validation PASS": pass_count,
                "Validation FAIL": fail_count,
            },
            key_findings=key_findings,
            affected_devices=[device for device, _count in affected.most_common(10)] or ["No affected devices identified."],
            risk_assessment=(
                "High risk activity is present and should be reviewed immediately."
                if highest_risk >= 70
                else "Current risk is moderate or low based on available telemetry."
            ),
            mitre_attack_summary=tactic_summary or ["No MITRE ATT&CK mappings available."],
            timeline_summary=self._timeline(alerts, incidents, validations),
            validation_summary=(
                f"Validation results: {pass_count} pass, {fail_count} fail, {len(validations)} total. "
                f"Metrics: TP={tp}, TN={tn}, FP={fp}, FN={fn}."
            ),
            recommended_actions=recommendations,
            conclusion="The system generated this analysis strictly from available EDR telemetry, alerts, incidents, mappings, validations, and report artifacts.",
            generated_at=generated_at,
            mode_used=f"{mode} (offline rule-based)",
            source_counts={key: len(value) for key, value in data.items() if isinstance(value, list)},
        )

    def _try_llm_summary(self, data: dict[str, Any], settings: AIAnalystSettings) -> str:
        mode = settings.mode.lower()
        prompt = self._llm_prompt(data)
        if mode == "ollama":
            base_url = (settings.api_base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
            model = settings.model_name or os.getenv("OLLAMA_MODEL", "llama3.1")
            payload = {"model": model, "stream": False, "prompt": prompt}
            url = f"{base_url}/api/generate"
            headers = {"Content-Type": "application/json"}
        elif mode in {"openai", "openai-compatible"}:
            api_key = settings.api_key or os.getenv("OPENAI_API_KEY", "")
            if not api_key:
                return ""
            base_url = (settings.api_base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
            model = settings.model_name or os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "Summarize only the supplied EDR data. Do not invent facts."},
                    {"role": "user", "content": prompt},
                ],
            }
            url = f"{base_url}/chat/completions"
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        else:
            return ""

        request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                parsed = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            return ""
        if mode == "ollama":
            return str(parsed.get("response", "")).strip()
        return str(parsed.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()

    def _report_from_llm_text(self, base_report: AIReport, llm_text: str, mode: str) -> AIReport:
        return AIReport(
            executive_summary=llm_text,
            threat_overview=base_report.threat_overview,
            key_findings=base_report.key_findings,
            affected_devices=base_report.affected_devices,
            risk_assessment=base_report.risk_assessment,
            mitre_attack_summary=base_report.mitre_attack_summary,
            timeline_summary=base_report.timeline_summary,
            validation_summary=base_report.validation_summary,
            recommended_actions=base_report.recommended_actions,
            conclusion=base_report.conclusion,
            generated_at=base_report.generated_at,
            mode_used=mode,
            source_counts=base_report.source_counts,
        )

    def _llm_prompt(self, data: dict[str, Any]) -> str:
        safe = {key: value[:50] if isinstance(value, list) else value for key, value in data.items()}
        return (
            "Create an AI SECURITY ANALYSIS REPORT with Executive Summary, Threat Overview, Key Findings, "
            "Affected Devices, Risk Assessment, MITRE ATT&CK Summary, Timeline Summary, Validation Summary, "
            "Recommended Actions, and Conclusion. Only use this JSON data:\n"
            f"{json.dumps(safe, default=str, sort_keys=True)}"
        )

    def _timeline(self, alerts: list[dict], incidents: list[dict], validations: list[dict]) -> list[str]:
        items = []
        for row in alerts[:5]:
            items.append(f"{row.get('created_at_utc', '')}: Alert - {row.get('title', '')}")
        for row in incidents[:5]:
            items.append(f"{row.get('updated_at_utc', row.get('opened_at_utc', ''))}: Incident - {row.get('title', '')}")
        for row in validations[:5]:
            items.append(f"{row.get('created_at_utc', '')}: Validation - {row.get('test_name', '')} {row.get('pass_fail', '')}")
        return [item for item in items if item.strip(": ")] or ["No timeline data available."]

    def _rows(self, conn: sqlite3.Connection, table: str, order_column: str, limit: int) -> list[dict]:
        if not self._table_exists(conn, table):
            return []
        columns = self._columns(conn, table)
        order = order_column if order_column in columns else columns[0]
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY {order} DESC LIMIT ?", (limit,)).fetchall()]

    def _connection_rows(self, conn: sqlite3.Connection, limit: int) -> list[dict]:
        if self._table_exists(conn, "connections"):
            return self._rows(conn, "connections", "last_seen_utc", limit)
        if self._table_exists(conn, "sensor_events"):
            rows = conn.execute(
                "SELECT * FROM sensor_events WHERE event_type = 'network.connection_observed' ORDER BY timestamp_utc DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]
        return []

    def _dns_rows(self, conn: sqlite3.Connection, limit: int) -> list[dict]:
        if self._table_exists(conn, "dns_logs"):
            return self._rows(conn, "dns_logs", "timestamp_utc", limit)
        if self._table_exists(conn, "sensor_events"):
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM sensor_events WHERE event_type LIKE 'dns.%' ORDER BY timestamp_utc DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]
        return []

    def _traffic_rows(self, conn: sqlite3.Connection, limit: int) -> list[dict]:
        if self._table_exists(conn, "traffic_logs"):
            return self._rows(conn, "traffic_logs", "timestamp_utc", limit)
        if self._table_exists(conn, "sensor_events"):
            return [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT * FROM sensor_events
                    WHERE event_type LIKE 'network.%' AND event_type != 'network.connection_observed'
                    ORDER BY timestamp_utc DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            ]
        return []

    def _report_rows(self, conn: sqlite3.Connection, limit: int) -> list[dict]:
        if self._table_exists(conn, "reports"):
            return self._rows(conn, "reports", "generated_at_utc", limit)
        if self._table_exists(conn, "report_artifacts"):
            return self._rows(conn, "report_artifacts", "created_at_utc", limit)
        return []

    def _report_files(self, limit: int) -> list[dict]:
        report_root = PROJECT_ROOT / "reports"
        if not report_root.exists():
            return []
        files = sorted(
            [path for path in report_root.rglob("*") if path.is_file() and path.suffix.lower() in {".txt", ".md", ".json"}],
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        results = []
        for path in files[:limit]:
            text = path.read_text(encoding="utf-8", errors="ignore")
            results.append({"path": str(path), "preview": text[:2000], "updated": datetime.fromtimestamp(path.stat().st_mtime).isoformat()})
        return results

    def _alerts_linked_to_incidents(self, alerts: list[dict], incidents: list[dict]) -> list[dict]:
        related_ids = set()
        for incident in incidents:
            metadata = self._json(incident.get("metadata_json", "{}"))
            related_ids.update(metadata.get("alert_ids", []))
        return [alert for alert in alerts if alert.get("alert_id") in related_ids]

    def _empty_report(self, mode: str) -> AIReport:
        generated_at = datetime.now().isoformat(timespec="seconds")
        return AIReport(
            executive_summary="No telemetry or incidents available for analysis.",
            threat_overview={
                "Total Alerts": 0,
                "Open Incidents": 0,
                "Unknown Devices": 0,
                "Suspicious DNS Events": 0,
                "Highest Risk Score": 0,
            },
            key_findings=["No confirmed findings are available."],
            affected_devices=["No affected devices identified."],
            risk_assessment="No risk can be assessed because no telemetry or incidents are available.",
            mitre_attack_summary=["No MITRE ATT&CK mappings available."],
            timeline_summary=["No timeline data available."],
            validation_summary="No validation results available.",
            recommended_actions=["Generate telemetry, run validation tests, or ingest sensor events before analysis."],
            conclusion="No telemetry or incidents available for analysis.",
            generated_at=generated_at,
            mode_used=f"{mode} (offline rule-based)",
            source_counts={},
        )

    def _is_empty(self, data: dict[str, Any]) -> bool:
        return not any(data.get(key) for key in ("alerts", "incidents", "connections", "dns_logs", "traffic_logs", "validation_results", "reports", "report_files"))

    def _store_report_artifact(self, report: AIReport, outputs: dict[str, str]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO report_artifacts (
                    report_id, report_type, subject_id, title, body, metadata_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    "AI Security Analysis",
                    "ai_analysis",
                    "AI Security Analysis Report",
                    report.to_text(),
                    json.dumps({"outputs": outputs, "mode_used": report.mode_used}, sort_keys=True),
                    report.generated_at,
                ),
            )

    def _try_write_docx(self, path: Path, report: AIReport) -> Path | None:
        try:
            with zipfile.ZipFile(path, "w") as package:
                package.writestr("[Content_Types].xml", DOCX_CONTENT_TYPES)
                package.writestr("_rels/.rels", DOCX_RELS)
                package.writestr("word/document.xml", self._docx_document(report.to_text()))
            return path
        except OSError:
            return None

    def _try_write_pdf(self, path: Path, report: AIReport) -> Path | None:
        try:
            text = report.to_text().replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            lines = text.splitlines()[:60]
            content = "BT /F1 10 Tf 50 780 Td 14 TL " + " T* ".join(f"({line[:100]})" for line in lines) + " ET"
            objects = [
                b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
                b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
                b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
                b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
                f"5 0 obj << /Length {len(content.encode('latin-1', errors='ignore'))} >> stream\n{content}\nendstream endobj\n".encode("latin-1", errors="ignore"),
            ]
            with path.open("wb") as handle:
                handle.write(b"%PDF-1.4\n")
                offsets = []
                for obj in objects:
                    offsets.append(handle.tell())
                    handle.write(obj)
                xref = handle.tell()
                handle.write(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode())
                for offset in offsets:
                    handle.write(f"{offset:010d} 00000 n \n".encode())
                handle.write(f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
            return path
        except OSError:
            return None

    def _docx_document(self, text: str) -> str:
        paragraphs = "".join(f"<w:p><w:r><w:t>{self._xml_escape(line)}</w:t></w:r></w:p>" for line in text.splitlines())
        return f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{paragraphs}</w:body></w:document>'

    def _xml_escape(self, value: str) -> str:
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _ensure_validation_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS validation_results (
                    result_id TEXT PRIMARY KEY,
                    test_name TEXT NOT NULL,
                    expected_result TEXT NOT NULL,
                    actual_result TEXT NOT NULL,
                    pass_fail TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS report_artifacts (
                    report_id TEXT PRIMARY KEY,
                    report_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS validation_metrics (
                    metric_id TEXT PRIMARY KEY,
                    result_id TEXT,
                    test_name TEXT NOT NULL,
                    expected_positive INTEGER NOT NULL,
                    detected_positive INTEGER NOT NULL,
                    true_positive INTEGER NOT NULL DEFAULT 0,
                    true_negative INTEGER NOT NULL DEFAULT 0,
                    false_positive INTEGER NOT NULL DEFAULT 0,
                    false_negative INTEGER NOT NULL DEFAULT 0,
                    response_time_ms INTEGER NOT NULL DEFAULT 0,
                    cpu_usage_percent REAL NOT NULL DEFAULT 0,
                    memory_usage_mb REAL NOT NULL DEFAULT 0,
                    ioc_matches INTEGER NOT NULL DEFAULT 0,
                    cve_matches INTEGER NOT NULL DEFAULT 0,
                    created_at_utc TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _table_exists(self, conn: sqlite3.Connection, table: str) -> bool:
        return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone() is not None

    def _columns(self, conn: sqlite3.Connection, table: str) -> list[str]:
        return [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]

    def _json(self, value: str) -> dict:
        try:
            parsed = json.loads(value or "{}")
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}


DOCX_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

DOCX_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""


def generate_ai_security_summary(
    db_path: Path = DEFAULT_DB_PATH,
    settings: AIAnalystSettings | None = None,
    scope: str = "all",
) -> AIReport:
    return AIReportIntelligence(db_path).generate_ai_security_summary(settings=settings, scope=scope)
