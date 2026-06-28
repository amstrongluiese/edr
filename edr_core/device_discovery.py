from __future__ import annotations

import ipaddress
import csv
import re
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from .db import execute, fetch_all, utc_now
from .detection import analyze_event
from .ingestion import ingest
from .sessions import get_current_session_id
from .subprocess_utils import run_hidden


ARP_RE = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F:-]{11,17})\s+(?P<kind>\w+)")
IPCONFIG_IPV4_RE = re.compile(r"IPv4 Address[^:]*:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
IPCONFIG_MASK_RE = re.compile(r"Subnet Mask[^:]*:\s*(?P<mask>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
NSLOOKUP_NAME_RE = re.compile(r"Name:\s*(?P<name>\S+)", re.IGNORECASE)

VENDOR_PREFIXES = {
    "00:1a:11": "Google",
    "00:1b:63": "Apple",
    "00:1c:b3": "Apple",
    "00:23:12": "Apple",
    "3c:5a:b4": "Google",
    "44:65:0d": "Amazon",
    "50:c7:bf": "TP-Link",
    "70:4f:57": "TP-Link",
    "78:8a:20": "Ubiquiti",
    "a4:77:33": "Google",
    "ac:cf:23": "Xiaomi",
    "b8:27:eb": "Raspberry Pi",
    "bc:92:6b": "Apple",
    "d8:31:34": "Samsung",
    "dc:a6:32": "Raspberry Pi",
    "f0:18:98": "Apple",
    "f4:f5:d8": "Google",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _run(command: list[str], timeout: int = 8) -> str:
    return run_hidden(command, timeout)


def _normalize_mac(mac: str | None) -> str:
    if not mac:
        return ""
    clean = mac.strip().lower().replace("-", ":")
    parts = [part.zfill(2) for part in clean.split(":") if part]
    return ":".join(parts)


def lookup_vendor(mac: str | None) -> str:
    normalized = _normalize_mac(mac)
    prefix = ":".join(normalized.split(":")[:3])
    return VENDOR_PREFIXES.get(prefix, "unknown")


def estimate_device_type(hostname: str | None, vendor: str | None, ip: str | None = None) -> str:
    name = (hostname or "").lower()
    vendor_name = (vendor or "").lower()
    if ip and ip.endswith(".1"):
        return "router/gateway"
    if any(token in name for token in ["iphone", "ipad", "android", "phone", "mobile"]):
        return "phone/tablet"
    if any(token in name for token in ["printer", "epson", "canon", "brother", "hp-print"]):
        return "printer"
    if any(token in name for token in ["tv", "roku", "chromecast", "firetv"]):
        return "smart-tv/media"
    if any(token in name for token in ["ap", "accesspoint", "ubnt", "unifi"]):
        return "access-point"
    if "raspberry" in vendor_name or "iot" in name:
        return "iot"
    if any(token in name for token in ["laptop", "desktop", "pc", "workstation"]):
        return "computer"
    return "unknown/unclassified"


@lru_cache(maxsize=2048)
def hostname_lookup(ip: str) -> str:
    if ip.startswith(("224.", "239.", "255.", "0.", "169.254.")):
        return ""
    output = _run(["nslookup", ip], timeout=1)
    match = NSLOOKUP_NAME_RE.search(output)
    return match.group("name") if match else ""


def _is_device_ip(ip: str, mac: str = "") -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
        return False
    if ip.endswith(".255") or _normalize_mac(mac) == "ff:ff:ff:ff:ff:ff":
        return False
    return True


def discover_from_arp_table() -> list[dict[str, Any]]:
    output = _run(["arp", "-a"])
    devices: list[dict[str, Any]] = []
    for match in ARP_RE.finditer(output):
        ip = match.group("ip")
        mac = _normalize_mac(match.group("mac"))
        if not _is_device_ip(ip, mac):
            continue
        vendor = lookup_vendor(mac)
        hostname = hostname_lookup(ip)
        devices.append(
            {
                "event_type": "device",
                "timestamp": _now(),
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": estimate_device_type(hostname, vendor, ip),
                "trust_status": "unknown",
                "online_status": "online",
                "discovery_source": "arp_table",
            }
        )
    return devices


def discover_from_neighbor_table() -> list[dict[str, Any]]:
    output = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object {$_.State -notin @('Unreachable','Incomplete')} | "
            "Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Csv -NoTypeInformation",
        ]
    )
    devices: list[dict[str, Any]] = []
    for row in csv.DictReader(output.splitlines()) if output else []:
        ip = (row.get("IPAddress") or "").strip()
        mac = _normalize_mac(row.get("LinkLayerAddress"))
        if not _is_device_ip(ip, mac):
            continue
        vendor = lookup_vendor(mac)
        hostname = hostname_lookup(ip)
        devices.append(
            {
                "event_type": "device",
                "timestamp": _now(),
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": estimate_device_type(hostname, vendor, ip),
                "trust_status": "unknown",
                "online_status": "online",
                "discovery_source": "windows_neighbor_table",
            }
        )
    return devices


def local_subnets() -> list[ipaddress.IPv4Network]:
    output = _run(["ipconfig"])
    ips_and_masks: list[tuple[str, str]] = []
    pending_ip = ""
    for line in output.splitlines():
        ip_match = IPCONFIG_IPV4_RE.search(line)
        mask_match = IPCONFIG_MASK_RE.search(line)
        if ip_match:
            pending_ip = ip_match.group("ip")
        elif mask_match and pending_ip:
            ips_and_masks.append((pending_ip, mask_match.group("mask")))
            pending_ip = ""
    networks = []
    for ip, mask in ips_and_masks:
        if ip.startswith(("127.", "169.254.")):
            continue
        try:
            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        if network not in networks:
            networks.append(network)
    private_networks = [network for network in networks if network.is_private]
    return (private_networks or networks)[:2]


def _ping(ip: str) -> bool:
    output = _run(["ping", "-n", "1", "-w", "150", ip], timeout=1)
    return "TTL=" in output.upper()


def ping_sweep(limit_hosts: int = 65_534, max_workers: int = 96) -> list[str]:
    responsive: list[str] = []
    targets = []
    for network in local_subnets():
        targets.extend(str(host) for index, host in enumerate(network.hosts()) if index < limit_hosts)
    if not targets:
        return responsive
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_ping, ip): ip for ip in targets}
        for future in as_completed(futures):
            if future.result():
                responsive.append(futures[future])
    return sorted(set(responsive), key=lambda value: tuple(int(part) for part in value.split(".")))


def discover_network_devices(active_scan: bool = True) -> list[dict[str, Any]]:
    discovered: dict[str, dict[str, Any]] = {}

    for raw in discover_from_arp_table() + discover_from_neighbor_table():
        discovered[raw["ip"]] = raw

    if active_scan:
        for ip in ping_sweep():
            existing = discovered.get(ip, {})
            hostname = existing.get("hostname") or hostname_lookup(ip)
            mac = existing.get("mac", "")
            vendor = existing.get("vendor") or lookup_vendor(mac)
            source = existing.get("discovery_source", "")
            source = ",".join(sorted({part for part in [*source.split(","), "ping_sweep", "subnet_scan"] if part}))
            discovered[ip] = {
                "event_type": "device",
                "timestamp": _now(),
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor or "unknown",
                "device_type": existing.get("device_type") or estimate_device_type(hostname, vendor, ip),
                "trust_status": existing.get("trust_status", "unknown"),
                "online_status": "online",
                "discovery_source": source,
            }

        # A ping sweep populates ARP on Windows, so read the table again for MAC enrichment.
        for raw in discover_from_arp_table():
            existing = discovered.get(raw["ip"], {})
            source = existing.get("discovery_source", "")
            raw["discovery_source"] = ",".join(sorted({part for part in [*source.split(","), "arp_table", "post_ping_arp"] if part}))
            discovered[raw["ip"]] = {**existing, **raw}

    return list(discovered.values())


def import_discovered_devices(active_scan: bool = True) -> int:
    session_id = get_current_session_id()
    execute(
        "DELETE FROM devices WHERE (ip LIKE '224.%' OR ip LIKE '239.%' OR ip LIKE '255.%' OR ip LIKE '%.255') AND ((? IS NULL AND session_id IS NULL) OR session_id = ?)",
        (session_id, session_id),
    )
    count = 0
    discovered = discover_network_devices(active_scan=active_scan)
    seen_ips = {raw["ip"] for raw in discovered}
    for raw in discovered:
        event = ingest(raw)
        analyze_event(event)
        count += 1
    rows = fetch_all(
        "SELECT id, ip, missed_scans, online_status FROM devices WHERE is_inventory_device = 1 AND ((? IS NULL AND session_id IS NULL) OR session_id = ?)",
        (session_id, session_id),
    )
    for row in rows:
        if row["ip"] in seen_ips:
            execute("UPDATE devices SET missed_scans = 0, online_status = 'online' WHERE id = ?", (row["id"],))
            continue
        missed = int(row["missed_scans"] or 0) + 1
        status = "offline" if missed >= 6 else "recently_seen" if missed >= 3 else row["online_status"]
        execute("UPDATE devices SET missed_scans = ?, online_status = ? WHERE id = ?", (missed, status, row["id"]))
    execute(
        "INSERT INTO performance_metrics(timestamp, metric_name, metric_value, unit, context, session_id) VALUES (?, ?, ?, ?, ?, ?)",
        (utc_now(), "device_discovery_count", count, "devices", "{}", get_current_session_id()),
    )
    return count


def main() -> None:
    count = import_discovered_devices(active_scan=True)
    print(f"Imported {count} visible local-network devices.")


if __name__ == "__main__":
    main()
