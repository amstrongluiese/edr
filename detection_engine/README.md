# Python Detection Engine

Python application layer for ingestion, detection orchestration, enrichment, persistence, and reporting.

## Phase 3 Features

- Ingests JSONL events from the C++ sensor.
- Stores raw events in SQLite.
- Performs risk scoring.
- Maps findings to MITRE ATT&CK techniques.
- Runs behavioral analysis.
- Runs DNS analysis.
- Detects telemetry from previously unknown devices.
- Phase 7 rules generate SQLite alerts for unknown devices, suspicious DNS,
  beaconing, repeated connections, port discovery, and large data transfers.
- Populates canonical operational tables for connections, DNS logs, and traffic
  logs while preserving raw `sensor_events`.
- Correlates events against a local SQLite `threat_intelligence` cache for
  offline IoC/CVE-style matching.
- Phase 5.5 evidence-based scoring keeps weak single signals informational and
  promotes risk only when measurable evidence accumulates.
- Optional cache refresh helpers support URLhaus, MalwareBazaar, ThreatFox, and
  NVD/CVE cache files; runtime detection works offline from local cache data.

## Phase 6 AI Security Analyst

The AI Security Analyst module accepts structured security context:

- Risk score
- Alerts
- Incidents
- MITRE ATT&CK mappings
- Threat intelligence matches

It outputs:

- Executive Summary
- Technical Findings
- Recommendations
- Incident Narrative

It supports:

- Deterministic local report generation
- Ollama via `OLLAMA_BASE_URL` and `OLLAMA_MODEL`
- OpenAI API via `OPENAI_API_KEY`, `OPENAI_MODEL`, and optional `OPENAI_BASE_URL`

Run the sample:

```powershell
$env:PYTHONPATH = "detection_engine/src"
py -m edr_engine.ai_analyst.sample
```

Generate from SQLite:

```powershell
$env:PYTHONPATH = "detection_engine/src"
py -m edr_engine.ai_analyst.cli --db data/edr.sqlite --provider deterministic
py -m edr_engine.ai_analyst.cli --db data/edr.sqlite --provider ollama
py -m edr_engine.ai_analyst.cli --db data/edr.sqlite --provider openai
```

## Run

```powershell
$env:PYTHONPATH = "detection_engine/src"
py -m edr_engine.cli output/sensor-events.jsonl --db data/edr.sqlite
```

The engine applies migrations from `database/migrations` before ingestion.

## Threat Intelligence Cache

The offline cache lives in `threat_intel/`:

- `malicious_ips.txt`
- `malicious_domains.txt`
- `malicious_urls.txt`
- `malicious_hashes.txt`
- `mitre_attack.json`
- `cve_cache.json`

Import cached indicators into SQLite:

```powershell
$env:PYTHONPATH = "detection_engine/src"
python -m edr_engine.threat_intel.cli --cache-dir threat_intel --db data/edr.sqlite
```

Optional online refresh commands require valid API keys where the provider
requires them:

```powershell
$env:PYTHONPATH = "detection_engine/src"
$env:ABUSECH_AUTH_KEY = "<your abuse.ch auth key>"
python -m edr_engine.threat_intel.feed_refresh --urlhaus --threatfox --malwarebazaar --cache-dir threat_intel
python -m edr_engine.threat_intel.feed_refresh --nvd --cache-dir threat_intel
python -m edr_engine.threat_intel.cli --cache-dir threat_intel --db data/edr.sqlite
```

Risk scoring uses these evidence weights:

- Unknown device: +5
- New device first seen: +5
- Risky open port: +15
- Repeated connections: +20
- Suspicious DNS: +25
- Beaconing: +30
- Port scan: +30
- Traffic spike: +20
- Malicious IP/domain/URL: +40
- Malicious hash: +50
- Critical CVE: +50

Risk levels:

- 0-10: Informational
- 11-30: Low Risk
- 31-60: Suspicious
- 61-80: High Risk
- 81-100: Critical
