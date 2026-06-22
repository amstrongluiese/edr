from __future__ import annotations

import csv
import hashlib
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import MONITORED_EXTENSIONS, SCAN_PATH_NAMES, SUSPICIOUS_PATH_MARKERS
from .db import execute, init_db, json_dumps, record_metric, utc_now
from .detection import analyze_event
from .ingestion import ingest
from .performance import record_system_metrics
from .risk import risk_level
from .sessions import get_current_session_id


def _run(command: list[str], timeout: int = 20) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout


def signature_status(path: Path) -> bool | None:
    if not path.exists() or path.suffix.lower() not in {".exe", ".dll", ".msi", ".scr"}:
        return None
    escaped = str(path).replace("'", "''")
    output = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(Get-AuthenticodeSignature -LiteralPath '{escaped}' -ErrorAction SilentlyContinue).Status",
        ],
        timeout=5,
    ).strip()
    if not output:
        return None
    return output.lower() == "valid"


def sha256_file(path: Path, max_bytes: int = 80_000_000) -> str:
    digest = hashlib.sha256()
    try:
        if path.stat().st_size > max_bytes:
            return ""
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def scan_roots() -> list[Path]:
    home = Path.home()
    roots = []
    for name in SCAN_PATH_NAMES:
        path = home / name
        if path.exists():
            roots.append(path)
    startup = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    if startup.exists():
        roots.append(startup)
    return roots


def _file_risk(path: Path, file_hash: str) -> tuple[int, dict[str, Any]]:
    path_lower = str(path).lower()
    score = 0
    evidence: dict[str, Any] = {"path": str(path), "sha256": file_hash}
    if path.suffix.lower() in MONITORED_EXTENSIONS:
        evidence["monitored_extension"] = path.suffix.lower()
    if any(marker in path_lower for marker in SUSPICIOUS_PATH_MARKERS):
        score += 15
        evidence["suspicious_path"] = True
    if "\\startup\\" in path_lower:
        score += 15
        evidence["startup_persistence"] = True
    return min(score, 100), evidence


def scan_files(limit_per_root: int = 250) -> int:
    session_id = get_current_session_id()
    count = 0
    for root in scan_roots():
        scanned = 0
        for path in root.rglob("*"):
            if scanned >= limit_per_root:
                break
            if not path.is_file() or path.suffix.lower() not in MONITORED_EXTENSIONS:
                continue
            scanned += 1
            file_hash = sha256_file(path)
            score, evidence = _file_risk(path, file_hash)
            raw = {
                "event_type": "file_scan",
                "timestamp": utc_now(),
                "file_path": str(path),
                "sha256": file_hash,
                "signed": signature_status(path),
                "source": "full_endpoint_scan",
            }
            event = ingest(raw)
            analyze_event(event)
            execute(
                """
                INSERT INTO scan_results(timestamp, scan_type, target, item_type, risk_score, risk_level, evidence, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (utc_now(), "full_endpoint_scan", str(path), "file", score, risk_level(score), json_dumps(evidence), session_id),
            )
            count += 1
    return count


def scan_processes() -> int:
    session_id = get_current_session_id()
    output = _run(["tasklist", "/fo", "csv", "/v"], timeout=20)
    rows: list[dict[str, str]] = []
    if output:
        rows = list(csv.DictReader(output.splitlines()))
    if not rows:
        output = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Csv -NoTypeInformation",
            ],
            timeout=20,
        )
        rows = list(csv.DictReader(output.splitlines())) if output else []

    count = 0
    for row in rows:
        name = row.get("Image Name") or row.get("ImageName") or row.get("ProcessName") or ""
        pid = row.get("PID") or row.get("Id") or "0"
        path = row.get("Path") or ""
        raw = {
            "event_type": "process_scan",
            "timestamp": utc_now(),
            "process_name": name,
            "pid": int(pid) if pid.isdigit() else None,
            "command_line": row.get("Window Title") or "",
            "executable_path": path,
            "sha256": sha256_file(Path(path)) if path else "",
            "source": "full_endpoint_scan",
        }
        event = ingest(raw)
        analyze_event(event)
        execute(
            "INSERT INTO scan_results(timestamp, scan_type, target, item_type, risk_score, risk_level, evidence, session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (utc_now(), "full_endpoint_scan", name, "process", 0, "Informational", json_dumps(raw), session_id),
        )
        count += 1
    return count


def scan_open_ports() -> int:
    output = _run(["netstat", "-ano", "-p", "tcp"], timeout=20)
    count = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        local = parts[1]
        remote = parts[2]
        pid = parts[-1]
        if ":" not in local:
            continue
        local_ip, local_port = local.rsplit(":", 1)
        remote_ip, remote_port = remote.rsplit(":", 1) if ":" in remote else ("", "")
        raw = {
            "event_type": "connection",
            "timestamp": utc_now(),
            "source_ip": local_ip,
            "destination_ip": remote_ip,
            "source_port": int(local_port) if local_port.isdigit() else None,
            "port": int(remote_port) if remote_port.isdigit() else int(local_port) if local_port.isdigit() else None,
            "protocol": "TCP",
            "pid": int(pid) if pid.isdigit() else None,
            "direction": "inbound/listening" if remote_ip in {"0.0.0.0", "[::]", "*"} or remote_port in {"0", "*"} else "outbound/active",
            "source": "full_endpoint_scan",
        }
        event = ingest(raw)
        analyze_event(event)
        count += 1
    return count


def scan_installed_software() -> int:
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion | ConvertTo-Csv -NoTypeInformation",
    ]
    output = _run(command, timeout=30)
    if not output:
        return 0
    count = 0
    for row in csv.DictReader(output.splitlines()):
        name = row.get("DisplayName") or ""
        version = row.get("DisplayVersion") or ""
        if not name:
            continue
        raw = {
            "event_type": "device",
            "timestamp": utc_now(),
            "ip": "local-endpoint",
            "hostname": os.environ.get("COMPUTERNAME", "local-endpoint"),
            "trust_status": "trusted",
            "software": [{"name": name, "version": version}],
            "source": "installed_software_scan",
        }
        event = ingest(raw)
        analyze_event(event)
        count += 1
    return count


def scan_startup_programs() -> int:
    session_id = get_current_session_id()
    startup_paths = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ]
    count = 0
    for root in startup_paths:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            raw = {
                "event_type": "file_scan",
                "timestamp": utc_now(),
                "file_path": str(path),
                "sha256": sha256_file(path),
                "signed": signature_status(path),
                "source": "startup_scanner",
            }
            event = ingest(raw)
            analyze_event(event)
            execute(
                "INSERT INTO scan_results(timestamp, scan_type, target, item_type, risk_score, risk_level, evidence, session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (utc_now(), "startup_scan", str(path), "startup_file", 15, "Low Risk", json_dumps(raw), session_id),
            )
            count += 1
    return count


def scan_services() -> int:
    session_id = get_current_session_id()
    output = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Csv -NoTypeInformation",
        ],
        timeout=30,
    )
    rows = list(csv.DictReader(output.splitlines())) if output else []
    if not rows:
        output = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Service | Select-Object Name,DisplayName,Status | ConvertTo-Csv -NoTypeInformation",
            ],
            timeout=20,
        )
        rows = list(csv.DictReader(output.splitlines())) if output else []
    count = 0
    for row in rows:
        path = (row.get("PathName") or "").strip('"')
        raw = {
            "event_type": "service_scan",
            "timestamp": utc_now(),
            "process_name": row.get("Name") or row.get("DisplayName"),
            "command_line": path,
            "executable_path": path.split(" ")[0] if path else "",
            "source": "service_scanner",
            "service_state": row.get("State") or row.get("Status"),
            "start_mode": row.get("StartMode"),
        }
        event = ingest({**raw, "event_type": "process_scan"})
        analyze_event(event)
        execute(
            "INSERT INTO scan_results(timestamp, scan_type, target, item_type, risk_score, risk_level, evidence, session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (utc_now(), "service_scan", row.get("DisplayName") or row.get("Name") or "service", "service", 0, "Informational", json_dumps(raw), session_id),
        )
        count += 1
    return count


def collect_windows_event_logs(limit: int = 60) -> int:
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624,4625}} -MaxEvents {limit} -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Csv -NoTypeInformation"
        ),
    ]
    output = _run(command, timeout=30)
    rows = list(csv.DictReader(output.splitlines())) if output else []
    source_name = "Windows Security Event Log"
    if not rows:
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Get-WinEvent -LogName System -MaxEvents {limit} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Csv -NoTypeInformation",
        ]
        output = _run(command, timeout=30)
        rows = list(csv.DictReader(output.splitlines())) if output else []
        source_name = "Windows System Event Log"
    count = 0
    for row in rows:
        message = row.get("Message") or ""
        outcome = "failed" if row.get("Id") == "4625" else "success" if row.get("Id") == "4624" else ""
        raw = {
            "event_type": "auth_log" if source_name == "Windows Security Event Log" else "application_log",
            "timestamp": row.get("TimeCreated") or utc_now(),
            "log_source": source_name,
            "username": "",
            "source_ip": "",
            "target_system": os.environ.get("COMPUTERNAME", "local-endpoint"),
            "outcome": outcome,
            "raw_line": message[:1000],
        }
        event = ingest(raw)
        analyze_event(event)
        count += 1
    return count


def run_full_scan() -> dict[str, int | float]:
    init_db()
    start = time.perf_counter()
    results = {
        "processes": scan_processes(),
        "services": scan_services(),
        "startup_items": scan_startup_programs(),
        "open_ports": scan_open_ports(),
        "files": scan_files(),
        "installed_software": scan_installed_software(),
        "windows_events": collect_windows_event_logs(),
    }
    elapsed_ms = (time.perf_counter() - start) * 1000
    record_metric("full_scan_time", elapsed_ms, "ms", results)
    record_system_metrics("full_endpoint_scan")
    return {**results, "elapsed_ms": round(elapsed_ms, 2)}


def main() -> None:
    print(run_full_scan())


if __name__ == "__main__":
    main()
