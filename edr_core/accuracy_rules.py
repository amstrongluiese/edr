from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .config import BASE_DIR
from .models import NormalizedEvent


CONFIG_DIR = BASE_DIR / "config"
SIGMA_DIR = BASE_DIR / "rules" / "sigma"
YARA_DIR = BASE_DIR / "rules" / "yara"


def _lines(path: Path) -> set[str]:
    try:
        return {
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except OSError:
        return set()


@lru_cache(maxsize=1)
def safe_baseline() -> dict[str, set[str]]:
    return {
        "domains": _lines(CONFIG_DIR / "safe_domains.txt"),
        "ips": _lines(CONFIG_DIR / "safe_ips.txt"),
        "processes": _lines(CONFIG_DIR / "safe_processes.txt"),
        "vendors": _lines(CONFIG_DIR / "safe_vendors.txt"),
    }


def domain_is_safe(domain: str | None) -> bool:
    value = (domain or "").strip(".").lower()
    return any(value == item or value.endswith("." + item) for item in safe_baseline()["domains"])


def ip_is_safe(ip: str | None) -> bool:
    return (ip or "").lower() in safe_baseline()["ips"]


def process_is_safe(process: str | None) -> bool:
    return (process or "").lower() in safe_baseline()["processes"]


def vendor_is_safe(vendor: str | None) -> bool:
    value = (vendor or "").lower()
    return any(item in value for item in safe_baseline()["vendors"])


@lru_cache(maxsize=1)
def sigma_rules() -> tuple[dict[str, Any], ...]:
    rules: list[dict[str, Any]] = []
    if SIGMA_DIR.exists():
        for path in sorted(SIGMA_DIR.glob("*.yml")):
            try:
                rules.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
    return tuple(rules)


def match_sigma(event: NormalizedEvent) -> list[dict[str, Any]]:
    process = (event.process_name or "").lower()
    command = (event.command_line or "").lower()
    matches = []
    for rule in sigma_rules():
        process_hit = process in {item.lower() for item in rule.get("processes", [])}
        marker_hits = [item for item in rule.get("command_markers", []) if item.lower() in command]
        if marker_hits and (process_hit or not rule.get("processes")):
            matches.append({**rule, "matched_markers": marker_hits, "source": "offline_sigma_cache"})
        elif process_hit and process in {"mimikatz.exe", "procdump.exe", "psexec.exe"}:
            matches.append({**rule, "matched_markers": [process], "source": "offline_sigma_cache"})
    return matches


def match_yara_like(event: NormalizedEvent) -> list[dict[str, Any]]:
    if event.event_type not in {"file", "file_event", "file_scan", "process", "process_event", "process_scan"}:
        return []
    text = " ".join([event.command_line or "", str(event.raw.get("content_sample") or "")]).lower()
    markers = [item for item in ("frombase64string", "downloadstring", "invoke-expression") if item in text]
    if not markers:
        return []
    return [{
        "rule": "Suspicious_Encoded_Script",
        "matched_markers": markers,
        "source": "offline_yara_compatible_rule",
        "score": 35,
    }]
