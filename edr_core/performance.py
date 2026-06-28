from __future__ import annotations

import os

from .db import record_metric
from .subprocess_utils import run_hidden


def sample_system_metrics() -> dict[str, float]:
    """Record lightweight CPU and memory samples for the current Python process."""
    pid = str(os.getpid())
    output = run_hidden(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"$p=Get-Process -Id {pid}; [pscustomobject]@{{CPU=$p.CPU;MemoryMB=[math]::Round($p.WorkingSet64/1MB,2)}} | ConvertTo-Csv -NoTypeInformation",
        ],
        timeout=5,
    )
    lines = [line.strip().strip('"') for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        return {"cpu_seconds": 0.0, "memory_mb": 0.0}
    values = [item.strip('"') for item in lines[1].split(",")]
    if len(values) != 2:
        return {"cpu_seconds": 0.0, "memory_mb": 0.0}
    try:
        cpu_seconds = float(values[0] or 0)
        memory_mb = float(values[1] or 0)
    except ValueError:
        return {"cpu_seconds": 0.0, "memory_mb": 0.0}
    return {"cpu_seconds": cpu_seconds, "memory_mb": memory_mb}


def record_system_metrics(context: str) -> dict[str, float]:
    sample = sample_system_metrics()
    cpu_seconds = sample["cpu_seconds"]
    memory_mb = sample["memory_mb"]
    record_metric("cpu_usage_process_time", cpu_seconds, "cpu_seconds", {"context": context})
    record_metric("memory_usage", memory_mb, "MB", {"context": context})
    return sample

