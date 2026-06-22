# Current EDR/XDR Audit

Status before this upgrade:

- C++ sensor: PARTIAL. Windows process, TCP, DNS cache telemetry scaffold exists; not a kernel/service-grade sensor.
- Python collectors: PARTIAL. Ingestion and network discovery exist; full endpoint scan, file monitor, and log import were missing.
- Python detection engine: WORKING/PARTIAL. Evidence-based network, DNS, IoC, CVE, risk, MITRE, and incident logic existed; endpoint/log detections were missing.
- SQLite database: WORKING/PARTIAL. Core tables existed; endpoint scan, file/process/log/failed-attempt/CVE-match tables were missing.
- Dashboard UI: WORKING/PARTIAL. Tkinter Windows dashboard exists; missing many EDR/XDR pages.
- Device inventory: WORKING. ARP, neighbor table, ping sweep, passive observation, host/vendor estimation, online status, and informational unknown-device handling exist.
- Validation simulator: WORKING/PARTIAL. Computes TP/TN/FP/FN and rates; missing endpoint/log test cases.
- Reports: WORKING/PARTIAL. Technical, validation, and AI reports exist; final overall report missing.
- AI analyst: WORKING/PARTIAL. Offline rule-based analyst uses recorded evidence; endpoint/log evidence not yet included.
- Threat intelligence: WORKING/PARTIAL. Offline cache exists; online feed refresh is not implemented.
- MITRE mapping: WORKING/PARTIAL. Core mappings exist; endpoint/log mappings were missing.
- Risk scoring: WORKING. Weighted evidence-based scoring exists; unknown devices remain informational.
- Performance metrics: PARTIAL. Detection/full-scan timing exists; live CPU/memory depends on environment support.

Upgrade actions:

- Added full endpoint scan module for processes, open ports, installed software, and monitored file locations.
- Added monitored file snapshot module for Downloads, Desktop, Documents, AppData, Temp, and Startup folders.
- Added log importer for auth/server/database/application-style CSV or text logs.
- Added failed-attempt detection for 3 failures and successful login after failures.
- Added endpoint file/process detections, malicious hash checks, suspicious path checks, startup persistence, database access attempts, and MITRE mappings.
- Added dashboard pages and controls for Full Scan, Files, Processes, Logs, Failed Attempts, Threat Intelligence, CVE Matches, and MITRE Mapping.
- Added install packaging helper scripts and documentation.

