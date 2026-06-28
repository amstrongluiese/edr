from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from statistics import mean
from typing import Iterable
from uuid import uuid4

from edr_engine.core.events import DetectionFinding, SensorEvent
from edr_engine.core.ports import DetectionProvider


REPEATED_CONNECTION_THRESHOLD = 5
REPEATED_WINDOW_SECONDS = 600
BEACON_MIN_EVENTS = 4
BEACON_INTERVAL_TOLERANCE_SECONDS = 8
PORT_DISCOVERY_DISTINCT_PORTS = 10
PORT_DISCOVERY_WINDOW_SECONDS = 300
LARGE_TRANSFER_BYTES = 50 * 1024 * 1024


class NetworkRulesProvider(DetectionProvider):
    def __init__(self) -> None:
        self._connection_history: dict[tuple[str, str, int], deque[datetime]] = defaultdict(deque)
        self._port_history: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
        self._emitted: set[tuple[str, tuple]] = set()

    @property
    def provider_id(self) -> str:
        return "phase7_network_rules"

    def evaluate(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        if event.event_type == "network.connection_observed":
            yield from self._evaluate_connection(event)

    def _evaluate_connection(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        remote_ip = str(event.payload.get("remote_address") or "")
        remote_port = int(event.payload.get("remote_port") or 0)
        if not remote_ip or remote_ip in {"0.0.0.0", "127.0.0.1"} or remote_port <= 0:
            return

        timestamp = event.timestamp_utc
        key = (event.asset_id, remote_ip, remote_port)
        history = self._connection_history[key]
        history.append(timestamp)
        self._trim_datetimes(history, timestamp, REPEATED_WINDOW_SECONDS)

        if len(history) >= REPEATED_CONNECTION_THRESHOLD and self._first_emit("repeated", key):
            yield self._finding(
                event,
                "Repeated outbound connection pattern",
                "medium",
                {
                    "category": "repeated_connection",
                    "basis": (
                        f"{len(history)} connections from {event.asset_id} to {remote_ip}:{remote_port} "
                        f"within {REPEATED_WINDOW_SECONDS // 60} minutes"
                    ),
                    "remote_address": remote_ip,
                    "remote_port": remote_port,
                    "connection_count": len(history),
                },
            )

        if self._looks_like_beacon(history) and self._first_emit("beacon", key):
            intervals = self._intervals(history)
            yield self._finding(
                event,
                "Possible beaconing connection pattern",
                "high",
                {
                    "category": "beaconing",
                    "basis": (
                        f"{len(history)} connections to {remote_ip}:{remote_port} with near-regular "
                        f"{round(mean(intervals), 1)} second intervals"
                    ),
                    "remote_address": remote_ip,
                    "remote_port": remote_port,
                    "connection_count": len(history),
                    "average_interval_seconds": round(mean(intervals), 2),
                },
            )

        port_key = (event.asset_id, remote_ip)
        port_history = self._port_history[port_key]
        port_history.append((timestamp, remote_port))
        self._trim_port_history(port_history, timestamp, PORT_DISCOVERY_WINDOW_SECONDS)
        distinct_ports = {port for _, port in port_history}
        if len(distinct_ports) >= PORT_DISCOVERY_DISTINCT_PORTS and self._first_emit("port_discovery", port_key):
            yield self._finding(
                event,
                "Possible port discovery activity",
                "high",
                {
                    "category": "port_discovery",
                    "basis": (
                        f"{event.asset_id} contacted {len(distinct_ports)} distinct ports on {remote_ip} "
                        f"within {PORT_DISCOVERY_WINDOW_SECONDS // 60} minutes"
                    ),
                    "remote_address": remote_ip,
                    "distinct_ports": sorted(distinct_ports),
                },
            )

        transferred = self._transfer_bytes(event)
        if transferred >= LARGE_TRANSFER_BYTES and self._first_emit("large_transfer", (event.asset_id, remote_ip, event.event_id)):
            yield self._finding(
                event,
                "Large outbound data transfer observed",
                "high",
                {
                    "category": "large_data_transfer",
                    "basis": f"{event.asset_id} transferred {transferred} bytes involving {remote_ip}",
                    "remote_address": remote_ip,
                    "bytes_transferred": transferred,
                },
            )

        if remote_port in {445, 3389} and self._first_emit("smb_rdp_access", key):
            access_type = "SMB" if remote_port == 445 else "RDP"
            yield self._finding(
                event,
                f"{access_type} access observed",
                "medium",
                {
                    "category": "smb_rdp_access",
                    "basis": f"{event.asset_id} contacted {access_type} service on {remote_ip}:{remote_port}",
                    "remote_address": remote_ip,
                    "remote_port": remote_port,
                    "access_type": access_type,
                },
            )

    def _looks_like_beacon(self, history: deque[datetime]) -> bool:
        if len(history) < BEACON_MIN_EVENTS:
            return False
        intervals = self._intervals(history)
        if len(intervals) < BEACON_MIN_EVENTS - 1:
            return False
        average = mean(intervals)
        if average <= 0:
            return False
        return all(abs(interval - average) <= BEACON_INTERVAL_TOLERANCE_SECONDS for interval in intervals[-3:])

    def _intervals(self, history: deque[datetime]) -> list[float]:
        values = list(history)
        return [(values[index] - values[index - 1]).total_seconds() for index in range(1, len(values))]

    def _transfer_bytes(self, event: SensorEvent) -> int:
        for key in (
            "bytes",
            "bytes_sent",
            "bytes_out",
            "outbound_bytes",
            "upload_bytes",
            "total_bytes",
            "size_bytes",
        ):
            value = event.payload.get(key)
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return 0

    def _trim_datetimes(self, history: deque[datetime], now: datetime, window_seconds: int) -> None:
        while history and (now - history[0]).total_seconds() > window_seconds:
            history.popleft()

    def _trim_port_history(self, history: deque[tuple[datetime, int]], now: datetime, window_seconds: int) -> None:
        while history and (now - history[0][0]).total_seconds() > window_seconds:
            history.popleft()

    def _first_emit(self, rule: str, key: tuple) -> bool:
        dedupe_key = (rule, key)
        if dedupe_key in self._emitted:
            return False
        self._emitted.add(dedupe_key)
        return True

    def _finding(
        self,
        event: SensorEvent,
        title: str,
        severity: str,
        metadata: dict,
    ) -> DetectionFinding:
        return DetectionFinding(
            finding_id=str(uuid4()),
            event_id=event.event_id,
            provider_id=self.provider_id,
            title=title,
            severity=severity,
            metadata=metadata,
        )
