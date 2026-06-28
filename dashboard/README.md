# CustomTkinter Dashboard

Operator-facing desktop dashboard.

The dashboard should call service interfaces and should not contain detection logic or direct persistence decisions.

## Phase 5 UI

The Phase 5 dashboard is a CustomTkinter enterprise-style shell using mock data only.

Pages:

- Dashboard
- Devices
- Threats
- Incidents
- Reports
- Settings
- Validation Simulator

The Validation Simulator runs safe synthetic telemetry through the real Python
detection engine and stores resulting alerts in SQLite. It includes:

- Unknown Device Test
- DNS Test
- Beaconing Test
- Repeated Connection Test
- Traffic Spike Test

Run:

```powershell
python -m pip install -r dashboard/requirements.txt
$env:PYTHONPATH = "dashboard/src"
python -m edr_dashboard.app
```

If PowerShell says `python` is not recognized, run it with the installed Python
path directly:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe" -m pip install -r dashboard/requirements.txt
$env:PYTHONPATH = "dashboard/src"
& "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe" -m edr_dashboard.app
```

This package does not implement detection logic or analytics.
