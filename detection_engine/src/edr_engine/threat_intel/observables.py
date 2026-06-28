from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from edr_engine.core.events import SensorEvent
from edr_engine.threat_intel.interfaces import Observable


HASH_KEYS = {
    "hash",
    "sha256",
    "hash_sha256",
    "file_hash",
    "process_hash",
}

DOMAIN_KEYS = {
    "query",
    "domain",
    "hostname",
    "dns_query",
    "remote_hostname",
    "url_domain",
}

IP_KEYS = {
    "source_ip",
    "destination_ip",
    "local_address",
    "remote_address",
    "ip_address",
}

URL_KEYS = {
    "url",
    "uri",
    "request_url",
}

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_observables(event: SensorEvent) -> list[Observable]:
    seen: set[tuple[str, str]] = set()
    observables: list[Observable] = []

    def add(kind: str, value: object) -> None:
        text = str(value or "").strip().strip(".")
        if not text:
            return
        normalized = _normalize(kind, text)
        if not normalized:
            return
        key = (kind, normalized)
        if key in seen:
            return
        seen.add(key)
        observables.append(Observable(value=normalized, kind=kind))

    for key, value in event.payload.items():
        lowered = key.lower()
        if lowered in IP_KEYS:
            add("ip", value)
        elif lowered in DOMAIN_KEYS:
            add("domain", value)
        elif lowered in HASH_KEYS:
            add("hash", value)
        elif lowered in URL_KEYS:
            add("url", value)
        elif "cve" in lowered:
            for cve in _iter_cves(str(value)):
                add("cve", cve)

        if isinstance(value, str):
            for cve in _iter_cves(value):
                add("cve", cve)

    return observables


def _iter_cves(value: str) -> Iterable[str]:
    for match in CVE_PATTERN.finditer(value):
        yield match.group(0)


def _normalize(kind: str, value: str) -> str:
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return ""
        if ip.is_loopback or ip.is_unspecified:
            return ""
        return str(ip)
    if kind == "domain":
        return value.lower()
    if kind == "hash":
        compact = value.lower()
        return compact if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", compact) else ""
    if kind == "url":
        return value
    if kind == "cve":
        return value.upper()
    return value

