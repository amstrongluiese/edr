# Enterprise-Inspired EDR System

This project is a defensive Endpoint Detection and Response demonstration for Windows 11 labs. It combines endpoint telemetry, device discovery, evidence-based detection, threat-intelligence correlation, MITRE ATT&CK mapping, risk scoring, incident correlation, validation metrics, AI-style analyst summaries, reporting, and a desktop dashboard.

The implementation is intentionally safe: the simulator creates benign and threat-like telemetry without performing exploitation, malware execution, or disruptive network activity.

## Architecture

```text
C++ Sensor Layer
  -> JSON telemetry
Python Ingestion
  -> normalization and SQLite persistence
Detection Engine
  -> behavioral evidence + IoC + CVE + MITRE mapping
Risk Engine
  -> explainable score and severity
Incident Correlator
  -> grouped alerts
Dashboard
  -> monitoring, validation, reports, AI analyst
```

## Quick Start

```powershell
python -m edr_core.seed_data
python run_dashboard.py
```

On this workstation, if `python` points to the Microsoft Store launcher stub, use:

```powershell
.\start_dashboard.ps1
```

Run the validation simulator from the dashboard, or from the command line:

```powershell
python -m edr_core.validation
```

Generate reports:

```powershell
python -m edr_core.reports
```

## New EDR/XDR Capabilities

- Full endpoint scan for processes, open ports, installed software, and monitored folders.
- File monitoring snapshot for Downloads, Desktop, Documents, AppData, Temp, and Startup.
- Imported authentication, database, web server, and application log analysis.
- Three-failed-attempt detection and successful-login-after-failures escalation.
- IoC matching for IPs, domains, URLs, hashes.
- CVE matching from the local offline cache.
- MITRE ATT&CK mapping on alerts.
- Final overall security report with TP/TN/FP/FN and accuracy metrics.

## C++ Sensor

The C++ sensor scaffold is in `sensor_cpp/`. It emits newline-delimited JSON telemetry to stdout or a file. Build on Windows with Visual Studio Developer PowerShell:

```powershell
cl /std:c++17 /EHsc sensor_cpp\edr_sensor.cpp /Fe:sensor_cpp\edr_sensor.exe /link Iphlpapi.lib Ws2_32.lib
```

Then run:

```powershell
sensor_cpp\edr_sensor.exe --output data\sensor_events.ndjson
python -m edr_core.ingest_file data\sensor_events.ndjson
```

## Safety Notes

- Unknown devices are informational by design.
- Alerts require explainable evidence and weighted scoring.
- Validation calculates TP, TN, FP, FN, accuracy, false-positive rate, false-negative rate, and response time.
- Threat intelligence is cached locally in `threat_intel/`; network refresh is optional.
- Visibility is limited to the local endpoint, visible same-network devices, visible endpoint traffic, imported logs, and collected Windows/local telemetry. It cannot see private activity inside another device unless an agent, router/firewall logs, or mirrored traffic is available.

## Installable Build

Use `build_installable.ps1` after installing PyInstaller:

```powershell
python -m pip install pyinstaller
.\build_installable.ps1
```

Expected installable layout:

```text
dist/EDR_System/
  EDR_System.exe
  threat_intel/
  reports/
  logs/
  config/
```
