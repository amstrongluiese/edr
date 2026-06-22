# Cybersecurity Capability Audit

This audit distinguishes real local telemetry and cache-backed detection from partial or future-work capabilities.

| Module | Status | Real Data Source | Missing Work |
|---|---|---|---|
| Process monitor | Working | tasklist fallback to PowerShell Get-Process; C++ Toolhelp snapshot scaffold | Continuous ETW/service process creation sensor is still future work. |
| File scanner | Working | Filesystem scan of Downloads/Desktop/Documents/AppData/Temp/Startup; SHA256 hashing; Authenticode best-effort | Commercial AV-grade unpacking and cloud reputation are not implemented. |
| Startup scanner | Working | User and ProgramData Windows Startup folders | Registry Run/RunOnce startup keys are not collected yet. |
| Service scanner | Working | PowerShell Get-CimInstance Win32_Service | Driver/service binary signature chain is only partial through process/file path checks. |
| Open port scanner | Working | netstat -ano TCP snapshot | UDP and firewall rule correlation are not implemented. |
| Active connection monitor | Working | netstat snapshot and C++ GetExtendedTcpTable scaffold; SQLite connections rows=705 | Continuous packet capture is not implemented. |
| DNS monitor | Partial | C++ ipconfig /displaydns cache collector and Python DNS telemetry ingestion | Continuous ETW DNS Client provider subscription is not implemented. |
| Windows Event Log reader | Partial | PowerShell Get-WinEvent Security 4624/4625 when permitted; falls back to System log events | Security authentication events require permission/admin for full access and richer username/IP parsing. |
| ARP scanner | Working | arp -a | Router ARP table import is not implemented. |
| Neighbor table scanner | Working | netsh interface ip show neighbors | IPv6 neighbor enrichment is limited. |
| Ping sweep/subnet scan | Working | Local IPv4 /24 sweep derived from ipconfig | Large routed network scanning is intentionally not attempted. |
| Device deduplication | Working | SQLite device_key using MAC primary, IP+hostname fallback; data_quality repair | OUIs use local curated prefixes, not full IEEE OUI database. |
| MAC vendor lookup | Partial | Local OUI prefix map in device_discovery.py | Full vendor database refresh not implemented. |
| Hostname resolver | Working | nslookup with bounded timeout | mDNS/NetBIOS hostname discovery is not implemented. |
| Inbound/outbound tracking | Working | connections.source_port, port, direction, source_ip, destination_ip | Direction is inferred from netstat snapshot, not packet-level state. |
| abuse.ch URLhaus | Partial | Offline malicious_urls/domains cache; optional refresh_open_source_feeds URLhaus downloader | Network refresh depends on internet access. |
| abuse.ch MalwareBazaar | Partial | Offline malicious_hashes cache; optional MalwareBazaar recent SHA256 refresh | No API-key authenticated advanced queries. |
| abuse.ch ThreatFox | Partial | Offline malicious_ips/domains cache; optional ThreatFox CSV refresh | CSV parsing is basic and IP-focused. |
| MITRE ATT&CK | Working | Local MITRE map in config.py and mitre_attack.json cache | Full ATT&CK STIX relationship browsing is not implemented. |
| NVD/CVE | Partial | Local cve_cache.json for known software/open-port exposures; cve_matches table rows=6 | Full NVD API CPE version matching is not implemented. |
| Local threat intel cache | Working | malicious_ips.txt, malicious_domains.txt, malicious_urls.txt, malicious_hashes.txt, mitre_attack.json, cve_cache.json | Cache quality depends on refresh/import cadence. |
| IoC matching | Working | match_iocs for IP, domain, URL, SHA256 hash | No fuzzy/domain-similarity matching. |
| CVE matching | Partial | Installed software scan and open-port exposure mapping against local CVE cache | Full CPE normalization and service banner grabbing are not implemented. |
| MITRE alert mapping | Working | alerts.mitre_tactic, mitre_technique, mitre_id | Mapping is curated per detection type. |
| Detection rules | Working | detection.py behavioral rules over SQLite-ingested telemetry and validation events | Rules are deterministic, not ML/anomaly baselines. |
| Evidence-based risk scoring | Working | Alert evidence JSON includes score_breakdown, reason, data_source, confidence, MITRE fields | Historical alerts before this audit may lack enriched fields until regenerated. |
| Validation metrics | Working | validation_results table; performance_metrics table; latest validation computes TP/TN/FP/FN/rates/response time | CPU is process CPU time sample, not full system profiler. |
| Fake/mock counts | Working | Dashboard counts use SQLite queries; validation test data is isolated to 10.240/10.241 and excluded from inventory | Demo validation records remain in SQLite history unless purged. |
