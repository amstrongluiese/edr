from __future__ import annotations

import os
import subprocess

from .db import record_metric


def record_system_metrics(context: str) -> None:
    """Record lightweight CPU and memory samples for the current Python process."""
    pid = str(os.getpid())
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"$p=Get-Process -Id {pid}; [pscustomobject]@{{CPU=$p.CPU;MemoryMB=[math]::Round($p.WorkingSet64/1MB,2)}} | ConvertTo-Csv -NoTypeInformation",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return
    lines = [line.strip().strip('"') for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        return
    values = [item.strip('"') for item in lines[1].split(",")]
    if len(values) != 2:
        return
    try:
        cpu_seconds = float(values[0] or 0)
        memory_mb = float(values[1] or 0)
    except ValueError:
        return
    record_metric("cpu_usage_process_time", cpu_seconds, "cpu_seconds", {"context": context})
    record_metric("memory_usage", memory_mb, "MB", {"context": context})

