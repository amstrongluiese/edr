from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def refresh_urlhaus(cache_dir: Path, auth_key: str) -> Path:
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    return _download(url, cache_dir / "urlhaus_recent.csv")


def refresh_malwarebazaar(cache_dir: Path, auth_key: str) -> Path:
    request = Request(
        "https://mb-api.abuse.ch/api/v1/",
        data=b"query=get_recent&selector=100",
        headers={"Auth-Key": auth_key, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    data = _read(request)
    path = cache_dir / "malwarebazaar_recent.json"
    path.write_bytes(data)
    return path


def refresh_threatfox(cache_dir: Path, auth_key: str, days: int = 7) -> Path:
    payload = json.dumps({"query": "get_iocs", "days": max(1, min(7, days))}).encode("utf-8")
    request = Request(
        "https://threatfox-api.abuse.ch/api/v1/",
        data=payload,
        headers={"Auth-Key": auth_key, "Content-Type": "application/json"},
        method="POST",
    )
    path = cache_dir / "threatfox_iocs.json"
    path.write_bytes(_read(request))
    return path


def refresh_nvd(cache_dir: Path, days: int = 7, api_key: str = "") -> Path:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=max(1, days))
    query = urlencode(
        {
            "pubStartDate": start.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "pubEndDate": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
    )
    headers = {"apiKey": api_key} if api_key else {}
    request = Request(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}", headers=headers)
    path = cache_dir / "cve_cache.json"
    path.write_bytes(_read(request))
    return path


def _download(url: str, path: Path) -> Path:
    request = Request(url, headers={"User-Agent": "NEW-EDR-threat-intel-cache/1.0"})
    path.write_bytes(_read(request))
    return path


def _read(request: Request) -> bytes:
    with urlopen(request, timeout=60) as response:
        return response.read()


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh optional online threat-intel cache files.")
    parser.add_argument("--cache-dir", type=Path, default=Path("threat_intel"))
    parser.add_argument("--abusech-auth-key", default=os.getenv("ABUSECH_AUTH_KEY", ""))
    parser.add_argument("--nvd-api-key", default=os.getenv("NVD_API_KEY", ""))
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--urlhaus", action="store_true")
    parser.add_argument("--malwarebazaar", action="store_true")
    parser.add_argument("--threatfox", action="store_true")
    parser.add_argument("--nvd", action="store_true")
    args = parser.parse_args()

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    refreshed = []
    if args.urlhaus:
        if not args.abusech_auth_key:
            raise SystemExit("URLhaus refresh requires --abusech-auth-key or ABUSECH_AUTH_KEY.")
        refreshed.append(refresh_urlhaus(args.cache_dir, args.abusech_auth_key))
    if args.malwarebazaar:
        if not args.abusech_auth_key:
            raise SystemExit("MalwareBazaar refresh requires --abusech-auth-key or ABUSECH_AUTH_KEY.")
        refreshed.append(refresh_malwarebazaar(args.cache_dir, args.abusech_auth_key))
    if args.threatfox:
        if not args.abusech_auth_key:
            raise SystemExit("ThreatFox refresh requires --abusech-auth-key or ABUSECH_AUTH_KEY.")
        refreshed.append(refresh_threatfox(args.cache_dir, args.abusech_auth_key, args.days))
    if args.nvd:
        refreshed.append(refresh_nvd(args.cache_dir, args.days, args.nvd_api_key))

    for path in refreshed:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

