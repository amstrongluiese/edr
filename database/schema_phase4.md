# Phase 4 SQLite Schema

This schema adds the operational tables used by the EDR dashboard and investigation workflow.

## Tables

### devices

Canonical endpoint inventory table. Links back to the earlier `assets` table through `asset_id`.

Important fields:

- `device_id`
- `hostname`
- `platform`
- `risk_score`
- `status`
- `first_seen_utc`
- `last_seen_utc`

### processes

Normalized process lifecycle records derived from sensor events.

Important fields:

- `process_record_id`
- `device_id`
- `event_id`
- `process_id`
- `parent_process_id`
- `image_name`
- `command_line`
- `started_at_utc`
- `ended_at_utc`
- `status`

### connections

Network connection records linked to devices, optional processes, and optional raw events.

Important fields:

- `connection_id`
- `device_id`
- `process_record_id`
- `protocol`
- `local_address`
- `local_port`
- `remote_address`
- `remote_port`
- `direction`
- `state`

### alerts

Analyst-facing alert records. Alerts can link to engine `findings` and raw `sensor_events`.

Important fields:

- `alert_id`
- `finding_id`
- `device_id`
- `event_id`
- `title`
- `severity`
- `risk_score`
- `status`
- `provider_id`

### incidents

Investigation containers that group related alerts.

Important fields:

- `incident_id`
- `title`
- `summary`
- `severity`
- `status`
- `owner`
- `opened_at_utc`
- `closed_at_utc`

### incident_alerts

Many-to-many link table between incidents and alerts.

### mitre_mappings

ATT&CK mappings for alerts or findings.

Important fields:

- `mapping_id`
- `alert_id`
- `finding_id`
- `technique_id`
- `tactic`
- `technique_name`
- `confidence`
- `source`

### reports

Generated analyst or AI report artifacts.

Important fields:

- `report_id`
- `incident_id`
- `device_id`
- `alert_id`
- `report_type`
- `title`
- `status`
- `body`
- `generated_at_utc`
- `exported_path`

## Relationship Summary

```text
devices 1 -> many processes
devices 1 -> many connections
devices 1 -> many alerts
processes 1 -> many connections
alerts many -> many incidents through incident_alerts
alerts/findings 1 -> many mitre_mappings
incidents/devices/alerts 1 -> many reports
sensor_events 1 -> optional processes/connections/alerts
```
