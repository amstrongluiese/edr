-- Initial schema placeholder for the hybrid EDR architecture.
-- This migration defines durable boundaries only; detection logic is intentionally absent.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    hostname TEXT,
    platform TEXT,
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sensor_events (
    event_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    source TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES sensor_events(event_id)
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tactic TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_mitre_techniques (
    finding_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (finding_id, technique_id),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(technique_id)
);

CREATE TABLE IF NOT EXISTS threat_intel_results (
    intel_id TEXT PRIMARY KEY,
    observable_value TEXT NOT NULL,
    observable_kind TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    reputation TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS report_artifacts (
    report_id TEXT PRIMARY KEY,
    report_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
