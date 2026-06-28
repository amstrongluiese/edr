from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import psutil


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "edr.sqlite"
DEFAULT_TRUSTED_DEVICES_PATH = PROJECT_ROOT / "config" / "trusted_devices.json"
FAST_SCAN_INTERVAL_SECONDS = 2.5


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_mac(value: str | None) -> str:
    if not value:
        return ""
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(compact) != 12:
        return value.strip().upper()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()


@dataclass(frozen=True)
class DiscoveredDevice:
    ip_address: str
    mac_address: str
    hostname: str
    vendor: str
    device_type: str
    first_seen: str
    last_seen: str
    trust_status: str
    risk_level: str
    discovery_source: str

    @property
    def key(self) -> str:
        return self.mac_address or self.ip_address

    def as_row(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    rows: list[dict]
    discovered_count: int
    new_count: int
    last_scan_time: str
    is_scanning: bool = False


@dataclass(frozen=True)
class ScanStatus:
    is_scanning: bool
    last_scan_time: str
    devices_found: int
    new_devices_found: int
    fast_scan_enabled: bool


class TrustedInventory:
    def __init__(self, path: Path = DEFAULT_TRUSTED_DEVICES_PATH) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text('{\n  "trusted_devices": []\n}\n', encoding="utf-8")
        self._devices = self._load()

    def _load(self) -> list[dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        devices = data.get("trusted_devices", [])
        return devices if isinstance(devices, list) else []

    def is_trusted(self, ip_address: str, mac_address: str) -> bool:
        normalized_mac = normalize_mac(mac_address)
        for device in self._devices:
            trusted_ip = str(device.get("ip_address", "")).strip()
            trusted_mac = normalize_mac(str(device.get("mac_address", "")))
            if trusted_ip and trusted_ip == ip_address:
                return True
            if trusted_mac and normalized_mac and trusted_mac == normalized_mac:
                return True
        return False


class LanDeviceRepository:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS lan_devices (
                    device_key TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    hostname TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    trust_status TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    discovery_source TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_lan_devices_ip ON lan_devices(ip_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_devices_mac ON lan_devices(mac_address)")

    def upsert_many(self, devices: list[DiscoveredDevice]) -> int:
        new_count = 0
        with self._connect() as conn:
            for device in devices:
                existing = conn.execute(
                    """
                    SELECT device_key, first_seen, discovery_source
                    FROM lan_devices
                    WHERE device_key = ? OR ip_address = ? OR (mac_address != '' AND mac_address = ?)
                    """,
                    (device.key, device.ip_address, device.mac_address),
                ).fetchone()
                if existing is None:
                    new_count += 1
                device_key = existing["device_key"] if existing else device.key
                first_seen = existing["first_seen"] if existing else device.first_seen
                discovery_source = device.discovery_source
                if existing and existing["discovery_source"]:
                    sources = {source.strip() for source in existing["discovery_source"].split(",") if source.strip()}
                    sources.update(source.strip() for source in device.discovery_source.split(",") if source.strip())
                    discovery_source = ", ".join(sorted(sources))

                conn.execute(
                    """
                    INSERT INTO lan_devices (
                        device_key,
                        ip_address,
                        mac_address,
                        hostname,
                        vendor,
                        device_type,
                        first_seen,
                        last_seen,
                        trust_status,
                        risk_level,
                        discovery_source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(device_key) DO UPDATE SET
                        ip_address = excluded.ip_address,
                        mac_address = excluded.mac_address,
                        hostname = excluded.hostname,
                        vendor = excluded.vendor,
                        device_type = excluded.device_type,
                        first_seen = ?,
                        last_seen = excluded.last_seen,
                        trust_status = excluded.trust_status,
                        risk_level = excluded.risk_level,
                        discovery_source = ?
                    """,
                    (
                        device_key,
                        device.ip_address,
                        device.mac_address,
                        device.hostname,
                        device.vendor,
                        device.device_type,
                        first_seen,
                        device.last_seen,
                        device.trust_status,
                        device.risk_level,
                        discovery_source,
                        first_seen,
                        discovery_source,
                    ),
                )
        return new_count

    def list_devices(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    ip_address,
                    mac_address,
                    hostname,
                    vendor,
                    device_type,
                    first_seen,
                    last_seen,
                    trust_status,
                    risk_level,
                    discovery_source
                FROM lan_devices
                ORDER BY trust_status DESC, last_seen DESC, ip_address
                """
            ).fetchall()
        return [dict(row) for row in rows]


class WindowsLanDiscovery:
    COMMON_OUI_VENDORS = {
        "001A11": "Google",
        "001B63": "Apple",
        "0023DF": "Apple",
        "002500": "Apple",
        "3C5A37": "Samsung",
        "503275": "Apple",
        "64B0A6": "Apple",
        "6C4008": "Apple",
        "7CD1C3": "Apple",
        "8C8590": "Apple",
        "A4C361": "Apple",
        "ACBC32": "Apple",
        "B827EB": "Raspberry Pi",
        "D850E6": "ASUSTek",
        "F0D1A9": "Apple",
    }

    def __init__(self, trusted_inventory: TrustedInventory | None = None) -> None:
        self.trusted_inventory = trusted_inventory or TrustedInventory()

    def discover(self, ping_sweep: bool = False) -> list[DiscoveredDevice]:
        if ping_sweep:
            self._ping_local_subnets()

        candidates: dict[str, dict] = {}
        for item in self._from_arp_table() + self._from_net_neighbor():
            ip_address = item["ip_address"]
            mac_address = normalize_mac(item.get("mac_address", ""))
            if not self._is_usable_ipv4(ip_address):
                continue
            key = mac_address or ip_address
            entry = candidates.setdefault(
                key,
                {"ip_address": ip_address, "mac_address": mac_address, "sources": set()},
            )
            if mac_address:
                entry["mac_address"] = mac_address
            entry["ip_address"] = ip_address
            entry["sources"].add(item["source"])

        seen_at = utc_now()
        devices = []
        for entry in candidates.values():
            ip_address = entry["ip_address"]
            mac_address = entry["mac_address"]
            hostname = self._resolve_hostname(ip_address)
            trust_status = "Trusted" if self.trusted_inventory.is_trusted(ip_address, mac_address) else "Unknown Device"
            devices.append(
                DiscoveredDevice(
                    ip_address=ip_address,
                    mac_address=mac_address or "Unknown",
                    hostname=hostname,
                    vendor=self._vendor_for_mac(mac_address),
                    device_type=self._estimate_device_type(hostname, mac_address),
                    first_seen=seen_at,
                    last_seen=seen_at,
                    trust_status=trust_status,
                    risk_level="Low" if trust_status == "Trusted" else "Suspicious",
                    discovery_source=", ".join(sorted(entry["sources"])),
                )
            )
        return devices

    def _run(self, command: list[str], timeout: int = 10) -> str:
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                creationflags=creationflags,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return completed.stdout or ""

    def _from_arp_table(self) -> list[dict]:
        output = self._run(["arp", "-a"])
        devices = []
        for line in output.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})\s+\w+", line)
            if match:
                devices.append(
                    {
                        "ip_address": match.group(1),
                        "mac_address": match.group(2),
                        "source": "ARP table",
                    }
                )
        return devices

    def _from_net_neighbor(self) -> list[dict]:
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json",
        ]
        output = self._run(command)
        try:
            parsed = json.loads(output) if output.strip() else []
        except json.JSONDecodeError:
            parsed = []
        if isinstance(parsed, dict):
            parsed = [parsed]

        devices = []
        for item in parsed:
            ip_address = str(item.get("IPAddress", "")).strip()
            mac_address = normalize_mac(str(item.get("LinkLayerAddress", "")))
            if ip_address and mac_address:
                devices.append(
                    {
                        "ip_address": ip_address,
                        "mac_address": mac_address,
                        "source": "NetNeighbor",
                    }
                )
        return devices

    def _local_subnets(self) -> list[ipaddress.IPv4Network]:
        networks = []
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family != socket.AF_INET or not address.netmask:
                    continue
                try:
                    interface = ipaddress.IPv4Interface(f"{address.address}/{address.netmask}")
                except ValueError:
                    continue
                if interface.ip.is_loopback or interface.ip.is_link_local:
                    continue
                networks.append(interface.network)
        return sorted(set(networks), key=str)

    def _ping_local_subnets(self) -> None:
        targets = []
        for network in self._local_subnets()[:4]:
            if network.prefixlen < 24:
                network = ipaddress.IPv4Network(f"{network.network_address}/24", strict=False)
            targets.extend(str(ip) for ip in network.hosts())
        if not targets:
            return

        def ping(ip_address: str) -> None:
            self._run(["ping", "-n", "1", "-w", "120", ip_address], timeout=1)

        with ThreadPoolExecutor(max_workers=128) as executor:
            list(executor.map(ping, targets[:512]))

    def _resolve_hostname(self, ip_address: str) -> str:
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            if hostname:
                return hostname
        except OSError:
            pass

        output = self._run(["nbtstat", "-A", ip_address], timeout=5)
        for line in output.splitlines():
            if "<00>" not in line or "GROUP" in line:
                continue
            name = line.split("<00>", 1)[0].strip()
            if name:
                return name
        return "Unknown"

    def _vendor_for_mac(self, mac_address: str) -> str:
        compact = re.sub(r"[^0-9a-fA-F]", "", mac_address).upper()
        if len(compact) < 6:
            return "Unknown"
        return self.COMMON_OUI_VENDORS.get(compact[:6], "Unknown")

    def _estimate_device_type(self, hostname: str, mac_address: str) -> str:
        text = f"{hostname} {self._vendor_for_mac(mac_address)}".lower()
        if any(token in text for token in ("iphone", "android", "samsung", "pixel", "huawei", "oppo", "vivo")):
            return "Phone"
        if any(token in text for token in ("ipad", "tablet")):
            return "Tablet"
        if any(token in text for token in ("router", "gateway", "asus", "tplink", "netgear")):
            return "Network Device"
        if any(token in text for token in ("desktop", "laptop", "windows", "pc")):
            return "Computer"
        return "Unknown"

    def _is_usable_ipv4(self, ip_address: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(ip_address)
        except ipaddress.AddressValueError:
            return False
        return not (ip.is_loopback or ip.is_multicast or ip.is_unspecified)


class DeviceInventoryService:
    def __init__(
        self,
        discovery: WindowsLanDiscovery | None = None,
        repository: LanDeviceRepository | None = None,
    ) -> None:
        self.discovery = discovery or WindowsLanDiscovery()
        self.repository = repository or LanDeviceRepository()
        self._callbacks: list[Callable[[ScanResult], None]] = []
        self._scan_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._fast_scan_enabled = False
        self._scanner_thread: threading.Thread | None = None
        self._status = ScanStatus(
            is_scanning=False,
            last_scan_time="Never",
            devices_found=0,
            new_devices_found=0,
            fast_scan_enabled=False,
        )

    def scan_network(self, ping_sweep: bool = True) -> list[dict]:
        return self.scan_network_with_status(ping_sweep=ping_sweep).rows

    def scan_network_with_status(self, ping_sweep: bool = True) -> ScanResult:
        if not self._scan_lock.acquire(blocking=False):
            rows = self.repository.list_devices()
            status = self.get_scan_status()
            return ScanResult(
                rows=rows,
                discovered_count=len(rows),
                new_count=0,
                last_scan_time=status.last_scan_time,
                is_scanning=True,
            )
        self._set_status(is_scanning=True)
        try:
            devices = self.discovery.discover(ping_sweep=ping_sweep)
            new_count = self.repository.upsert_many(devices)
            rows = self.repository.list_devices()
            last_scan_time = utc_now()
            result = ScanResult(
                rows=rows,
                discovered_count=len(devices),
                new_count=new_count,
                last_scan_time=last_scan_time,
            )
            self._set_status(
                is_scanning=False,
                last_scan_time=last_scan_time,
                devices_found=len(rows),
                new_devices_found=new_count,
            )
        except Exception:
            rows = self.repository.list_devices()
            last_scan_time = utc_now()
            result = ScanResult(
                rows=rows,
                discovered_count=0,
                new_count=0,
                last_scan_time=last_scan_time,
            )
            self._set_status(
                is_scanning=False,
                last_scan_time=last_scan_time,
                devices_found=len(rows),
                new_devices_found=0,
            )
        finally:
            if self._scan_lock.locked():
                self._scan_lock.release()
        if result.new_count:
            self._notify_callbacks(result)
        return result

    def start_fast_scan(self, interval_seconds: float = FAST_SCAN_INTERVAL_SECONDS) -> None:
        if self._scanner_thread and self._scanner_thread.is_alive():
            self._set_status(fast_scan_enabled=True)
            return
        self._stop_event.clear()
        self._set_status(fast_scan_enabled=True)

        def worker() -> None:
            while not self._stop_event.is_set():
                self.scan_network_with_status(ping_sweep=True)
                self._stop_event.wait(interval_seconds)
            self._set_status(is_scanning=False, fast_scan_enabled=False)

        self._scanner_thread = threading.Thread(target=worker, name="device-fast-scan", daemon=True)
        self._scanner_thread.start()

    def stop_fast_scan(self) -> None:
        self._stop_event.set()
        self._set_status(fast_scan_enabled=False)

    def register_scan_callback(self, callback: Callable[[ScanResult], None]) -> None:
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def get_scan_status(self) -> ScanStatus:
        with self._status_lock:
            return self._status

    def _set_status(
        self,
        *,
        is_scanning: bool | None = None,
        last_scan_time: str | None = None,
        devices_found: int | None = None,
        new_devices_found: int | None = None,
        fast_scan_enabled: bool | None = None,
    ) -> None:
        with self._status_lock:
            current = self._status
            self._status = ScanStatus(
                is_scanning=current.is_scanning if is_scanning is None else is_scanning,
                last_scan_time=current.last_scan_time if last_scan_time is None else last_scan_time,
                devices_found=current.devices_found if devices_found is None else devices_found,
                new_devices_found=current.new_devices_found if new_devices_found is None else new_devices_found,
                fast_scan_enabled=current.fast_scan_enabled if fast_scan_enabled is None else fast_scan_enabled,
            )

    def _notify_callbacks(self, result: ScanResult) -> None:
        for callback in list(self._callbacks):
            try:
                callback(result)
            except Exception:
                continue

    def list_devices(self) -> list[dict]:
        rows = self.repository.list_devices()
        self._set_status(devices_found=len(rows))
        return rows
