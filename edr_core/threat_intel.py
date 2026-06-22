from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .config import THREAT_INTEL_DIR
from .db import execute, fetch_all, init_db, json_dumps, utc_now


DEFAULT_INTEL = {
    "malicious_ips.txt": [
        "203.0.113.66",
        "198.51.100.23",
        "192.0.2.44",
    ],
    "malicious_domains.txt": [
        "malware-test.example",
        "command-control.example",
        "phishing-lab.invalid",
    ],
    "malicious_urls.txt": [
        "http://malware-test.example/dropper.exe",
        "http://command-control.example/beacon",
    ],
    "malicious_hashes.txt": [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ],
    "mitre_attack.json": {
        "source": "local curated MITRE ATT&CK subset",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
            {"id": "T1568.002", "name": "Domain Generation Algorithms", "tactic": "Command and Control"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        ],
    },
    "cve_cache.json": {
        "services": {
            "OpenSSH": {
                "7.2": {"cve": "CVE-2016-0777", "cvss": 7.5, "summary": "Roaming vulnerability in older OpenSSH clients."}
            },
            "Apache httpd": {
                "2.4.49": {"cve": "CVE-2021-41773", "cvss": 9.8, "summary": "Path traversal and file disclosure vulnerability."}
            },
            "Microsoft Exchange": {
                "2019-CU8": {"cve": "CVE-2021-26855", "cvss": 9.8, "summary": "Server-side request forgery vulnerability."}
            },
            "Remote Desktop Services": {
                "open-port-3389": {"cve": "CVE-2019-0708", "cvss": 9.8, "summary": "BlueKeep class RDP exposure requiring patch validation."}
            },
            "SMB": {
                "open-port-445": {"cve": "CVE-2017-0144", "cvss": 9.8, "summary": "EternalBlue class SMB exposure requiring patch validation."}
            },
        }
    },
}

FEED_SOURCES = {
    "urlhaus_urls": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "target": "malicious_urls.txt",
        "type": "url",
    },
    "threatfox_iocs": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "target": "malicious_ips.txt",
        "type": "mixed_ioc",
    },
    "malwarebazaar_hashes": {
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "target": "malicious_hashes.txt",
        "type": "hash",
    },
    "mitre_attack": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "target": "mitre_attack.json",
        "type": "json",
    },
}


def ensure_cache() -> None:
    THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
    for filename, content in DEFAULT_INTEL.items():
        path = THREAT_INTEL_DIR / filename
        if path.exists():
            continue
        if isinstance(content, list):
            path.write_text("\n".join(content) + "\n", encoding="utf-8")
        else:
            path.write_text(json.dumps(content, indent=2), encoding="utf-8")


def _load_lines(filename: str) -> set[str]:
    ensure_cache()
    path = THREAT_INTEL_DIR / filename
    return {line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def load_cves() -> dict[str, Any]:
    ensure_cache()
    return json.loads((THREAT_INTEL_DIR / "cve_cache.json").read_text(encoding="utf-8"))


def match_iocs(*, ip: str | None = None, domain: str | None = None, url: str | None = None, file_hash: str | None = None) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    if ip and ip.lower() in _load_lines("malicious_ips.txt"):
        matches.append({"type": "malicious_ip", "indicator": ip, "source": "local abuse.ch-style cache", "confidence": 90})
    if domain and domain.lower() in _load_lines("malicious_domains.txt"):
        matches.append({"type": "malicious_domain", "indicator": domain, "source": "local abuse.ch-style cache", "confidence": 90})
    if url and url.lower() in _load_lines("malicious_urls.txt"):
        matches.append({"type": "malicious_url", "indicator": url, "source": "local URLhaus-style cache", "confidence": 80})
    if file_hash and file_hash.lower() in _load_lines("malicious_hashes.txt"):
        matches.append({"type": "malicious_hash", "indicator": file_hash, "source": "local MalwareBazaar-style cache", "confidence": 95})
    return matches


def match_cves(software: list[dict[str, str]]) -> list[dict[str, Any]]:
    cves = load_cves().get("services", {})
    matches: list[dict[str, Any]] = []
    for item in software:
        name = item.get("name", "")
        version = item.get("version", "")
        hit = cves.get(name, {}).get(version)
        if hit:
            matches.append({"type": "critical_cve", "software": name, "version": version, **hit})
    return matches


def match_port_cves(port: int | None) -> list[dict[str, Any]]:
    if port is None:
        return []
    cves = load_cves().get("services", {})
    port_key = f"open-port-{port}"
    matches: list[dict[str, Any]] = []
    for product, versions in cves.items():
        hit = versions.get(port_key)
        if hit:
            matches.append({"type": "critical_cve", "software": product, "version": port_key, **hit})
    return matches


def refresh_open_source_feeds(timeout: int = 20) -> dict[str, str]:
    """Best-effort refresh. If network fails, existing offline cache remains authoritative."""
    ensure_cache()
    results: dict[str, str] = {}
    for name, spec in FEED_SOURCES.items():
        try:
            with urllib.request.urlopen(spec["url"], timeout=timeout) as response:
                text = response.read().decode("utf-8", errors="ignore")
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            results[name] = f"offline_cache_used: {exc.__class__.__name__}"
            continue
        path = THREAT_INTEL_DIR / spec["target"]
        if spec["type"] == "json":
            path.write_text(text, encoding="utf-8")
            results[name] = "refreshed"
            continue
        indicators = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if spec["type"] == "mixed_ioc":
                for part in line.replace('"', "").split(","):
                    part = part.strip()
                    if part.count(".") == 3 and all(chunk.isdigit() for chunk in part.split(".") if chunk):
                        indicators.append(part)
            else:
                indicators.append(line.split(",")[0].strip('"'))
        if indicators:
            existing = _load_lines(spec["target"])
            merged = sorted(existing | {item.lower() for item in indicators if item})
            path.write_text("\n".join(merged) + "\n", encoding="utf-8")
            results[name] = f"refreshed:{len(indicators)}"
        else:
            results[name] = "no_indicators_parsed"
    seed_intel_db()
    return results


def seed_intel_db() -> None:
    init_db()
    ensure_cache()
    now = utc_now()
    for filename, indicator_type, source in [
        ("malicious_ips.txt", "ip", "abuse.ch ThreatFox-style local cache"),
        ("malicious_domains.txt", "domain", "abuse.ch URLhaus-style local cache"),
        ("malicious_urls.txt", "url", "abuse.ch URLhaus-style local cache"),
        ("malicious_hashes.txt", "hash", "abuse.ch MalwareBazaar-style local cache"),
    ]:
        for indicator in _load_lines(filename):
            execute(
                """
                INSERT INTO threat_intelligence(indicator, indicator_type, source, confidence, first_seen, last_seen, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET last_seen=excluded.last_seen, details=excluded.details
                """,
                (indicator, indicator_type, source, 85, now, now, json_dumps({"cache_file": filename})),
            )


def threat_intel_counts() -> dict[str, int]:
    rows = fetch_all("SELECT indicator_type, COUNT(*) AS count FROM threat_intelligence GROUP BY indicator_type")
    return {row["indicator_type"]: int(row["count"]) for row in rows}
