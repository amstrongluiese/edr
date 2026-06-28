# SQLite Database

Database ownership layer for schemas, migrations, and repository adapters.

Application code should access storage through repository interfaces instead of issuing ad hoc SQL from UI or detection modules.

## Phase 4 Operational Schema

The Phase 4 schema is defined in `migrations/003_phase4_operational_schema.sql`.

It adds canonical operational tables for:

- `devices`
- `processes`
- `connections`
- `alerts`
- `incidents`
- `mitre_mappings`
- `reports`

See `schema_phase4.md` for table responsibilities and relationships.

## Enterprise Telemetry and Intelligence Schema

The enterprise extension is defined in `migrations/004_enterprise_intel_and_telemetry.sql`.

It adds:

- `dns_logs`
- `traffic_logs`
- `validation_results`
- `threat_intelligence`
- `threat_intel_matches`

The detection engine keeps raw `sensor_events` as the source of truth and also
projects selected events into operational tables for dashboard analytics,
incident review, AI analyst context, and local threat intelligence matching.

## True Detection Metrics

Phase 5.5 evaluation metrics are defined in
`migrations/005_true_detection_metrics.sql`.

It adds `validation_metrics` for:

- True positive / true negative / false positive / false negative counts
- Detection accuracy
- False positive and false negative rates
- Response time
- CPU and memory usage
- IoC and CVE match counts
