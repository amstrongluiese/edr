from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

from .db import execute, utc_now
from .detection import analyze_event
from .ingestion import ingest
from .session_events import record_session_event
from .sessions import get_current_session_id


DNS_RECORD_RE = re.compile(r"Record Name[ .]*:\s*(?P<domain>\S+)", re.IGNORECASE)
DOH_ENDPOINTS = {
    "cloudflare-dns.com": "Cloudflare DoH",
    "dns.google": "Google DoH",
    "dns.quad9.net": "Quad9 DoH",
    "dns.nextdns.io": "NextDNS DoH",
    "mozilla.cloudflare-dns.com": "Mozilla Cloudflare DoH",
}


def _run(command: list[str], timeout: int = 8) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout


def collect_dns_cache() -> dict[str, int | str]:
    session_id = get_current_session_id()
    if not session_id:
        return {"dns_events": 0, "status": "DNS telemetry unavailable"}
    output = _run(["ipconfig", "/displaydns"], timeout=8)
    domains = sorted({m.group("domain").strip(".").lower() for m in DNS_RECORD_RE.finditer(output) if "." in m.group("domain")})
    for domain in domains:
        event = ingest(
            {
                "event_type": "dns",
                "timestamp": utc_now(),
                "domain": domain,
                "query_type": "cache",
                "source_ip": "local-endpoint",
                "source": "windows_dns_cache",
            }
        )
        analyze_event(event)
        record_session_event("dns_observed", domain, {"domain": domain, "source": "windows_dns_cache"})
    status = "Standard DNS visible" if domains else "DNS telemetry unavailable"
    record_session_event("dns_status", "local-endpoint", {"status": status, "domain_count": len(domains)})
    return {"dns_events": len(domains), "status": status}


def detect_doh_connections() -> dict[str, int | str]:
    session_id = get_current_session_id()
    if not session_id:
        return {"doh_events": 0, "status": "DNS telemetry unavailable"}
    output = _run(["ipconfig", "/displaydns"], timeout=8).lower()
    hits = []
    for endpoint, provider in DOH_ENDPOINTS.items():
        if endpoint in output:
            hits.append({"endpoint": endpoint, "provider": provider})
            record_session_event("doh_detected", endpoint, {"endpoint": endpoint, "provider": provider}, "Low Risk")
    status = "Possible DoH detected" if hits else "Standard DNS visible"
    return {"doh_events": len(hits), "status": status}


def scan_browser_history(read_only_permission: bool = False, limit: int = 250) -> int:
    """Optional read-only browser history scanner. Caller must pass explicit permission."""
    if not read_only_permission or not get_current_session_id():
        return 0
    history_paths = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "History",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
    ]
    count = 0
    for path in history_paths:
        if not path.exists():
            continue
        temp = Path(os.environ.get("TEMP", ".")) / f"edr_history_{path.parent.name}.sqlite"
        try:
            shutil.copy2(path, temp)
            with sqlite3.connect(temp) as conn:
                rows = conn.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?", (limit,)).fetchall()
        except (OSError, sqlite3.Error):
            continue
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        for url, title, last_visit_time in rows:
            record_session_event("browser_history_observed", url, {"url": url, "title": title, "browser_history_time": last_visit_time})
            ingest({"event_type": "dns", "timestamp": utc_now(), "domain": str(url).split("/")[2] if "://" in str(url) else str(url), "source": "browser_history"})
            count += 1
    return count

