from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class ThreatIntelIndicator:
    value: str
    kind: str
    source: str
    reputation: str = "malicious"
    confidence: int = 80
    summary: str = ""
    cve_id: str = ""
    cve_severity: str = ""
    metadata: dict[str, Any] | None = None

    @property
    def indicator_id(self) -> str:
        digest = hashlib.sha1(f"{self.kind}:{self.value}:{self.source}".encode("utf-8")).hexdigest()[:16]
        return f"TI-{digest.upper()}"


class ThreatIntelCacheImporter:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir

    def load_all(self) -> list[ThreatIntelIndicator]:
        indicators: list[ThreatIntelIndicator] = []
        indicators.extend(self._load_plain("malicious_ips.txt", "ip", "local-cache:malicious_ips"))
        indicators.extend(self._load_plain("malicious_domains.txt", "domain", "local-cache:malicious_domains"))
        indicators.extend(self._load_plain("malicious_urls.txt", "url", "local-cache:malicious_urls"))
        indicators.extend(self._load_plain("malicious_hashes.txt", "hash", "local-cache:malicious_hashes"))
        indicators.extend(self._load_urlhaus_csv(self.cache_dir / "urlhaus_recent.csv"))
        indicators.extend(self._load_malwarebazaar_csv(self.cache_dir / "malwarebazaar_recent.csv"))
        indicators.extend(self._load_malwarebazaar_json(self.cache_dir / "malwarebazaar_recent.json"))
        indicators.extend(self._load_threatfox_json(self.cache_dir / "threatfox_iocs.json"))
        indicators.extend(self._load_nvd_cache(self.cache_dir / "cve_cache.json"))
        return self._dedupe(indicators)

    def _load_plain(self, filename: str, kind: str, source: str) -> list[ThreatIntelIndicator]:
        path = self.cache_dir / filename
        if not path.exists():
            return []
        indicators = []
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            normalized = self._normalize(kind, value)
            if normalized:
                indicators.append(
                    ThreatIntelIndicator(
                        value=normalized,
                        kind=kind,
                        source=source,
                        summary=f"{kind} listed in {filename}",
                    )
                )
        return indicators

    def _load_urlhaus_csv(self, path: Path) -> list[ThreatIntelIndicator]:
        if not path.exists():
            return []
        indicators = []
        for row in self._csv_rows(path):
            url = self._first(row, "url", "URL")
            if not url:
                continue
            indicators.append(
                ThreatIntelIndicator(
                    value=url,
                    kind="url",
                    source="abuse.ch:urlhaus",
                    confidence=90 if self._first(row, "url_status", "status").lower() == "online" else 75,
                    summary="URLhaus malware URL indicator",
                    metadata={"threat": self._first(row, "threat"), "tags": self._first(row, "tags")},
                )
            )
            host = urlparse(url).hostname or ""
            if host:
                indicators.append(
                    ThreatIntelIndicator(
                        value=host.lower(),
                        kind="domain",
                        source="abuse.ch:urlhaus",
                        confidence=85,
                        summary="Domain extracted from URLhaus malware URL",
                    )
                )
        return indicators

    def _load_malwarebazaar_csv(self, path: Path) -> list[ThreatIntelIndicator]:
        if not path.exists():
            return []
        indicators = []
        for row in self._csv_rows(path):
            sha256 = self._first(row, "sha256_hash", "sha256")
            if not sha256:
                continue
            indicators.append(
                ThreatIntelIndicator(
                    value=sha256.lower(),
                    kind="hash",
                    source="abuse.ch:malwarebazaar",
                    confidence=95,
                    summary="MalwareBazaar malware hash indicator",
                    metadata={
                        "signature": self._first(row, "signature"),
                        "file_type": self._first(row, "file_type"),
                        "tags": self._first(row, "tags"),
                    },
                )
            )
        return indicators

    def _load_malwarebazaar_json(self, path: Path) -> list[ThreatIntelIndicator]:
        if not path.exists():
            return []
        data = self._json(path)
        rows = data.get("data", data if isinstance(data, list) else [])
        if not isinstance(rows, list):
            return []
        indicators = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            sha256 = str(row.get("sha256_hash") or row.get("sha256") or "").strip().lower()
            if not sha256:
                continue
            indicators.append(
                ThreatIntelIndicator(
                    value=sha256,
                    kind="hash",
                    source="abuse.ch:malwarebazaar",
                    confidence=95,
                    summary="MalwareBazaar malware hash indicator",
                    metadata={
                        "signature": row.get("signature", ""),
                        "file_type": row.get("file_type", ""),
                        "tags": row.get("tags", []),
                    },
                )
            )
        return indicators

    def _load_threatfox_json(self, path: Path) -> list[ThreatIntelIndicator]:
        if not path.exists():
            return []
        data = self._json(path)
        rows = data.get("data", data if isinstance(data, list) else [])
        if not isinstance(rows, list):
            return []
        indicators = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            kind = self._map_kind(str(row.get("ioc_type") or row.get("type") or ""))
            value = self._normalize(kind, str(row.get("ioc") or row.get("value") or ""))
            if not kind or not value:
                continue
            confidence = int(row.get("confidence_level") or 80)
            indicators.append(
                ThreatIntelIndicator(
                    value=value,
                    kind=kind,
                    source="abuse.ch:threatfox",
                    confidence=max(0, min(100, confidence)),
                    summary=str(row.get("threat_type_desc") or "ThreatFox IOC"),
                    metadata={
                        "threat_type": row.get("threat_type", ""),
                        "malware": row.get("malware_printable") or row.get("malware", ""),
                        "first_seen": row.get("first_seen", ""),
                        "reference": row.get("reference", ""),
                    },
                )
            )
        return indicators

    def _load_nvd_cache(self, path: Path) -> list[ThreatIntelIndicator]:
        if not path.exists():
            return []
        data = self._json(path)
        rows = data.get("vulnerabilities") or data.get("cves") or []
        if not isinstance(rows, list):
            return []
        indicators = []
        for row in rows:
            cve = row.get("cve", row) if isinstance(row, dict) else {}
            if not isinstance(cve, dict):
                continue
            cve_id = str(cve.get("id") or row.get("cve_id") or "").upper()
            if not cve_id.startswith("CVE-"):
                continue
            severity, score = self._cve_severity(cve)
            cpes = self._cpe_terms(cve)
            indicators.append(
                ThreatIntelIndicator(
                    value=cve_id,
                    kind="cve",
                    source="nvd:cve",
                    reputation="suspicious",
                    confidence=90,
                    summary=f"NVD CVE record severity={severity or 'unknown'} score={score}",
                    cve_id=cve_id,
                    cve_severity=severity,
                    metadata={"cvss_score": score, "published": cve.get("published", ""), "cpe_terms": cpes},
                )
            )
        return indicators

    def _csv_rows(self, path: Path) -> Iterable[dict[str, str]]:
        lines = [line for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if not line.startswith("#")]
        if not lines:
            return []
        return csv.DictReader(lines)

    def _json(self, path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _first(self, row: dict[str, str], *keys: str) -> str:
        for key in keys:
            value = row.get(key)
            if value:
                return str(value).strip()
        return ""

    def _normalize(self, kind: str, value: str) -> str:
        value = value.strip().strip(".")
        if not value:
            return ""
        if kind == "domain":
            return value.lower()
        if kind == "hash":
            lowered = value.lower()
            return lowered if len(lowered) in {32, 40, 64} else ""
        if kind == "url":
            return value
        if kind == "cve":
            return value.upper()
        return value

    def _map_kind(self, raw: str) -> str:
        value = raw.lower()
        if value in {"ip", "ipv4", "ipv6", "ip:port"}:
            return "ip"
        if value in {"domain", "hostname"}:
            return "domain"
        if value in {"url"}:
            return "url"
        if "hash" in value:
            return "hash"
        return value

    def _cve_severity(self, cve: dict[str, Any]) -> tuple[str, float]:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key) or []
            if not values:
                continue
            cvss = values[0].get("cvssData", {})
            severity = str(values[0].get("cvssData", {}).get("baseSeverity") or values[0].get("baseSeverity") or "").lower()
            score = float(cvss.get("baseScore") or 0)
            if not severity and score:
                severity = self._severity_from_score(score)
            return severity, score
        return "", 0.0

    def _cpe_terms(self, cve: dict[str, Any]) -> list[str]:
        terms: set[str] = set()

        def visit(node: Any) -> None:
            if isinstance(node, dict):
                criteria = str(node.get("criteria") or "")
                parts = criteria.split(":")
                if criteria.startswith("cpe:2.3") and len(parts) >= 6:
                    for value in (parts[3], parts[4], parts[5]):
                        cleaned = value.replace("_", " ").replace("\\", "").strip("*-")
                        if len(cleaned) >= 3:
                            terms.add(cleaned.lower())
                for value in node.values():
                    visit(value)
            elif isinstance(node, list):
                for item in node:
                    visit(item)

        visit(cve.get("configurations", []))
        return sorted(terms)

    def _severity_from_score(self, score: float) -> str:
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        if score > 0:
            return "low"
        return ""

    def _dedupe(self, indicators: list[ThreatIntelIndicator]) -> list[ThreatIntelIndicator]:
        seen = set()
        unique = []
        for indicator in indicators:
            key = (indicator.kind, indicator.value, indicator.source)
            if key in seen:
                continue
            seen.add(key)
            unique.append(indicator)
        return unique


def import_cache_to_sqlite(cache_dir: Path, db_path: Path) -> int:
    indicators = ThreatIntelCacheImporter(cache_dir).load_all()
    now = utc_now()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        for indicator in indicators:
            conn.execute(
                """
                INSERT INTO threat_intelligence (
                    indicator_id,
                    observable_value,
                    observable_kind,
                    source,
                    reputation,
                    confidence,
                    summary,
                    cve_id,
                    cve_severity,
                    metadata_json,
                    created_at_utc,
                    updated_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(observable_kind, observable_value, source) DO UPDATE SET
                    reputation = excluded.reputation,
                    confidence = excluded.confidence,
                    summary = excluded.summary,
                    cve_id = excluded.cve_id,
                    cve_severity = excluded.cve_severity,
                    metadata_json = excluded.metadata_json,
                    updated_at_utc = excluded.updated_at_utc
                """,
                (
                    indicator.indicator_id,
                    indicator.value,
                    indicator.kind,
                    indicator.source,
                    indicator.reputation,
                    indicator.confidence,
                    indicator.summary,
                    indicator.cve_id or None,
                    indicator.cve_severity or None,
                    json.dumps(indicator.metadata or {}, sort_keys=True),
                    now,
                    now,
                ),
            )
    return len(indicators)
