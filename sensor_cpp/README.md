# C++ Sensor Layer

This Windows-oriented sensor emits newline-delimited JSON that the Python ingestion layer can consume.

Implemented telemetry:

- Process snapshot events
- TCP network connection events
- Basic DNS cache observations through `ipconfig /displaydns`
- Periodic heartbeat metadata

Build from Visual Studio Developer PowerShell:

```powershell
cl /std:c++17 /EHsc sensor_cpp\edr_sensor.cpp /Fe:sensor_cpp\edr_sensor.exe /link Iphlpapi.lib Ws2_32.lib
```

Run:

```powershell
sensor_cpp\edr_sensor.exe --output data\sensor_events.ndjson --interval 10
```

Ingest:

```powershell
python -m edr_core.ingest_file data\sensor_events.ndjson
```

Notes:

- This scaffold avoids kernel drivers and destructive actions.
- Process termination and advanced file activity monitoring require ETW or a Windows service wrapper in a production build.
- The output contract is stable JSON, so stronger collectors can replace this scaffold later without changing the Python detection pipeline.

