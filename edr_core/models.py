from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedEvent:
    event_type: str
    timestamp: str
    source_ip: str | None = None
    destination_ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    process_name: str | None = None
    pid: int | None = None
    domain: str | None = None
    query_type: str | None = None
    resolved_ip: str | None = None
    bytes_sent: int = 0
    bytes_received: int = 0
    bytes_total: int = 0
    window_seconds: int = 60
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    trust_status: str = "unknown"
    online_status: str = "online"
    discovery_source: str = "telemetry"
    open_ports: list[int] = field(default_factory=list)
    software: list[dict[str, str]] = field(default_factory=list)
    file_hash: str | None = None
    file_path: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    signed: bool | None = None
    username: str | None = None
    outcome: str | None = None
    target_system: str | None = None
    log_source: str | None = None
    url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertCandidate:
    alert_type: str
    entity: str
    score: int
    evidence: dict[str, Any]
    reason: str
