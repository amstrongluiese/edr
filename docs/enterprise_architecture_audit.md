# Enterprise EDR Architecture Audit

Audit date: 2026-06-20

## Executive Summary

This repository is an incremental hybrid EDR platform, not a blank scaffold. It already has a Windows C++ sensor, Python ingestion and detection engine, SQLite persistence, a live CustomTkinter dashboard, validation simulator, MITRE ATT&CK mapping, incident correlation, and AI report generation.

The main enterprise gaps are threat intelligence correlation, canonical telemetry table population, richer endpoint collection, transport options beyond JSONL, complete schema coverage for DNS/traffic/validation/intelligence, and automated tests. The safest path is to preserve the existing architecture and add missing enterprise modules behind the current engine, storage, and dashboard service boundaries.

## Target Data Flow

```text
Endpoint Sources
  -> C++ Sensor Layer
  -> Python Data Ingestion Layer
  -> Detection & Analysis Engine
  -> Threat Intelligence Correlation Layer
  -> MITRE ATT&CK Mapping Layer
  -> Risk Scoring Engine
  -> Incident Correlation Engine
  -> SQLite Storage
  -> Dashboard Visualization
  -> AI Security Analyst
  -> Reports & Validation
```

## Component Audit

| Module | Status | Evidence | Gaps |
| --- | --- | --- | --- |
| C++ Sensor Layer | Partial | `sensor_cpp` builds `edr_windows_sensor.exe`; collectors emit process create/terminate and TCP connection JSONL. | No file activity, Windows Event Log, DNS query collection, UDP, hash/signature metadata, buffering, named pipe, or service installer. |
| Python Ingestion Layer | Working | `edr_engine.cli` reads JSONL with `iter_jsonl_events()` and ingests into SQLite. | No named pipe/local IPC receiver; schema validation is structural only, not JSON Schema based. |
| Detection Engine | Partial | Unknown device, DNS, behavioral, repeated connection, beaconing, port discovery, large transfer, suspicious ports are implemented. | Detection is stateful only per engine run; no persisted baselines for network patterns; no threat-intel-backed detection yet. |
| SQLite Storage | Partial | Migrations define assets, sensor events, findings, risk, devices, connections, alerts, incidents, MITRE mappings, reports. | Canonical `connections`, `processes`, `dns_logs`, `traffic_logs`, `validation_results`, and `threat_intelligence` coverage is incomplete or populated indirectly. |
| Dashboard | Partial | `DashboardApp` uses `LiveDashboardService`; pages exist for dashboard, devices, alerts, connections, DNS, traffic, incidents, validation, AI analyst, reports, settings. | `mock_data.py` remains but is not the active service; some pages derive views from raw `sensor_events` because canonical telemetry tables are sparse. |
| Reports | Working | AI analysis exports TXT, JSON, DOCX, and PDF under `reports/ai_analysis`. | Incident and validation reports are folded into AI/report artifact flows rather than separate report generators. |
| Validation Simulator | Working | `CybersecurityValidationSimulator` runs safe synthetic scenarios through the real engine and writes pass/fail evidence. | Results table is created by dashboard helper, not a core migration; no test runner automation. |
| AI Components | Working | Deterministic analyst exists in `detection_engine`; dashboard AI report generator supports offline summaries and optional OpenAI/Ollama-style modes. | Threat-intel matches are modeled in the engine analyst but not loaded from SQLite yet. |
| MITRE Components | Working | Static mapping and persisted `mitre_mappings` exist for major detection categories. | Needs coverage expansion as new detection categories are added. |
| Threat Intelligence | Partial | Local `threat_intelligence` cache, observable extraction, IoC matching, CVE matching, and optional cache refresh/import helpers exist. | Live feed refresh requires user-provided API keys where providers require them; MISP remains optional/not wired. |

## Working Components

- C++ JSONL sensor output for process and TCP connection telemetry.
- Python JSONL ingestion and event normalization into `SensorEvent`.
- SQLite migrations and core persistence for raw events, findings, risk, alerts, incidents, MITRE mappings, and reports.
- Detection rules for unknown devices, suspicious DNS, beaconing, repeated connections, port discovery, large transfer, suspicious process behavior, and suspicious ports.
- MITRE ATT&CK mapping for current detection categories.
- Incident correlation for unknown device plus suspicious DNS plus beaconing.
- Live dashboard service against `data/edr.sqlite`.
- Validation simulator using the real detection engine.
- Offline AI analyst/report generation with optional external LLM support.

## Partial Components

- Sensor collection breadth.
- Canonical operational tables for processes, connections, DNS, and traffic analytics.
- Risk scoring weights; current severity-based scoring does not match all requested weighted enterprise rules.
- Dashboard pages that depend on derived raw events where canonical tables are not populated.
- AI analyst ingestion of threat intelligence context.
- Reports split by incident, validation, AI security, and technical report types.

## Mock Or Demo Components

- `dashboard/src/edr_dashboard/mock_data.py` remains in the tree but is not wired as the active dashboard service.
- Validation telemetry is intentionally synthetic and safe.
- Some existing SQLite files under `data/` are scenario/test databases.

## Missing Components

- MISP integration remains optional and not wired.
- Automated scheduled feed refresh is not yet packaged as a Windows service/task.
- Named pipe/local IPC ingestion.
- File activity sensor, Windows Event Log sensor, and DNS collection sensor.
- Windows install/service packaging.
- Automated unit/integration test suite.

## Incremental Upgrade Roadmap

1. Add core database migration for `dns_logs`, `traffic_logs`, `validation_results`, and `threat_intelligence`. Completed.
2. Populate canonical connection/process/DNS/traffic tables during ingestion while preserving raw `sensor_events`. Completed.
3. Add local threat-intel observable extraction, cache lookup, alert generation, and risk scoring integration. Completed.
4. Extend AI analyst context loading with threat-intelligence matches. Completed.
5. Add feed adapters with local cache refresh commands for abuse.ch and NVD, keeping network access optional. Completed as optional CLI refresh/import tooling.
6. Add named pipe/local IPC ingestion alongside JSONL.
7. Expand the C++ sensor with DNS, file, and Windows Event Log collectors.
8. Add focused unit/integration tests around parsing, detection, threat intelligence, persistence, and simulator scenarios.
9. Add Windows packaging/service documentation and scripts after the runtime paths are stable.
