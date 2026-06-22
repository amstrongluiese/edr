from __future__ import annotations

from pathlib import Path

from .config import BASE_DIR, THREAT_INTEL_DIR
from .db import fetch_one, init_db
from .threat_intel import ensure_cache


REPORT_PATH = BASE_DIR / "docs" / "CYBERSECURITY_CAPABILITY_AUDIT.md"


def _count(table: str) -> int:
    try:
        row = fetch_one(f"SELECT COUNT(*) AS count FROM {table}")
    except Exception:
        return 0
    return int(row["count"] if row else 0)


def _file_exists(name: str) -> bool:
    return (THREAT_INTEL_DIR / name).exists()


def audit_rows() -> list[dict[str, str]]:
    ensure_cache()
    init_db()
    return [
        {"Module": "Process monitor", "Status": "Working", "Real Data Source": "tasklist fallback to PowerShell Get-Process; C++ Toolhelp snapshot scaffold", "Missing Work": "Continuous ETW/service process creation sensor is still future work."},
        {"Module": "File scanner", "Status": "Working", "Real Data Source": "Filesystem scan of Downloads/Desktop/Documents/AppData/Temp/Startup; SHA256 hashing; Authenticode best-effort", "Missing Work": "Commercial AV-grade unpacking and cloud reputation are not implemented."},
        {"Module": "Startup scanner", "Status": "Working", "Real Data Source": "User and ProgramData Windows Startup folders", "Missing Work": "Registry Run/RunOnce startup keys are not collected yet."},
        {"Module": "Service scanner", "Status": "Working", "Real Data Source": "PowerShell Get-CimInstance Win32_Service", "Missing Work": "Driver/service binary signature chain is only partial through process/file path checks."},
        {"Module": "Open port scanner", "Status": "Working", "Real Data Source": "netstat -ano TCP snapshot", "Missing Work": "UDP and firewall rule correlation are not implemented."},
        {"Module": "Active connection monitor", "Status": "Working", "Real Data Source": "netstat snapshot and C++ GetExtendedTcpTable scaffold; SQLite connections rows=" + str(_count("connections")), "Missing Work": "Continuous packet capture is not implemented."},
        {"Module": "DNS monitor", "Status": "Partial", "Real Data Source": "C++ ipconfig /displaydns cache collector and Python DNS telemetry ingestion", "Missing Work": "Continuous ETW DNS Client provider subscription is not implemented."},
        {"Module": "Windows Event Log reader", "Status": "Partial", "Real Data Source": "PowerShell Get-WinEvent Security 4624/4625 when permitted; falls back to System log events", "Missing Work": "Security authentication events require permission/admin for full access and richer username/IP parsing."},
        {"Module": "ARP scanner", "Status": "Working", "Real Data Source": "arp -a", "Missing Work": "Router ARP table import is not implemented."},
        {"Module": "Neighbor table scanner", "Status": "Working", "Real Data Source": "netsh interface ip show neighbors", "Missing Work": "IPv6 neighbor enrichment is limited."},
        {"Module": "Ping sweep/subnet scan", "Status": "Working", "Real Data Source": "Local IPv4 /24 sweep derived from ipconfig", "Missing Work": "Large routed network scanning is intentionally not attempted."},
        {"Module": "Device deduplication", "Status": "Working", "Real Data Source": "SQLite device_key using MAC primary, IP+hostname fallback; data_quality repair", "Missing Work": "OUIs use local curated prefixes, not full IEEE OUI database."},
        {"Module": "MAC vendor lookup", "Status": "Partial", "Real Data Source": "Local OUI prefix map in device_discovery.py", "Missing Work": "Full vendor database refresh not implemented."},
        {"Module": "Hostname resolver", "Status": "Working", "Real Data Source": "nslookup with bounded timeout", "Missing Work": "mDNS/NetBIOS hostname discovery is not implemented."},
        {"Module": "Inbound/outbound tracking", "Status": "Working", "Real Data Source": "connections.source_port, port, direction, source_ip, destination_ip", "Missing Work": "Direction is inferred from netstat snapshot, not packet-level state."},
        {"Module": "abuse.ch URLhaus", "Status": "Partial", "Real Data Source": "Offline malicious_urls/domains cache; optional refresh_open_source_feeds URLhaus downloader", "Missing Work": "Network refresh depends on internet access."},
        {"Module": "abuse.ch MalwareBazaar", "Status": "Partial", "Real Data Source": "Offline malicious_hashes cache; optional MalwareBazaar recent SHA256 refresh", "Missing Work": "No API-key authenticated advanced queries."},
        {"Module": "abuse.ch ThreatFox", "Status": "Partial", "Real Data Source": "Offline malicious_ips/domains cache; optional ThreatFox CSV refresh", "Missing Work": "CSV parsing is basic and IP-focused."},
        {"Module": "MITRE ATT&CK", "Status": "Working", "Real Data Source": "Local MITRE map in config.py and mitre_attack.json cache", "Missing Work": "Full ATT&CK STIX relationship browsing is not implemented."},
        {"Module": "NVD/CVE", "Status": "Partial", "Real Data Source": "Local cve_cache.json for known software/open-port exposures; cve_matches table rows=" + str(_count("cve_matches")), "Missing Work": "Full NVD API CPE version matching is not implemented."},
        {"Module": "Local threat intel cache", "Status": "Working", "Real Data Source": ", ".join(name for name in ["malicious_ips.txt", "malicious_domains.txt", "malicious_urls.txt", "malicious_hashes.txt", "mitre_attack.json", "cve_cache.json"] if _file_exists(name)), "Missing Work": "Cache quality depends on refresh/import cadence."},
        {"Module": "IoC matching", "Status": "Working", "Real Data Source": "match_iocs for IP, domain, URL, SHA256 hash", "Missing Work": "No fuzzy/domain-similarity matching."},
        {"Module": "CVE matching", "Status": "Partial", "Real Data Source": "Installed software scan and open-port exposure mapping against local CVE cache", "Missing Work": "Full CPE normalization and service banner grabbing are not implemented."},
        {"Module": "MITRE alert mapping", "Status": "Working", "Real Data Source": "alerts.mitre_tactic, mitre_technique, mitre_id", "Missing Work": "Mapping is curated per detection type."},
        {"Module": "Detection rules", "Status": "Working", "Real Data Source": "detection.py behavioral rules over SQLite-ingested telemetry and validation events", "Missing Work": "Rules are deterministic, not ML/anomaly baselines."},
        {"Module": "Evidence-based risk scoring", "Status": "Working", "Real Data Source": "Alert evidence JSON includes score_breakdown, reason, data_source, confidence, MITRE fields", "Missing Work": "Historical alerts before this audit may lack enriched fields until regenerated."},
        {"Module": "Validation metrics", "Status": "Working", "Real Data Source": "validation_results table; performance_metrics table; latest validation computes TP/TN/FP/FN/rates/response time", "Missing Work": "CPU is process CPU time sample, not full system profiler."},
        {"Module": "Fake/mock counts", "Status": "Working", "Real Data Source": "Dashboard counts use SQLite queries; validation test data is isolated to 10.240/10.241 and excluded from inventory", "Missing Work": "Demo validation records remain in SQLite history unless purged."},
    ]


def generate_audit_report() -> Path:
    rows = audit_rows()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Cybersecurity Capability Audit",
        "",
        "This audit distinguishes real local telemetry and cache-backed detection from partial or future-work capabilities.",
        "",
        "| Module | Status | Real Data Source | Missing Work |",
        "|---|---|---|---|",
    ]
    for row in rows:
        lines.append(f"| {row['Module']} | {row['Status']} | {row['Real Data Source']} | {row['Missing Work']} |")
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return REPORT_PATH


def main() -> None:
    print(generate_audit_report())


if __name__ == "__main__":
    main()
