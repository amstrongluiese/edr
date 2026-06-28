-- Phase 4 operational schema.
-- Canonical tables for dashboard, investigation, and reporting workflows.

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    asset_id TEXT UNIQUE,
    hostname TEXT NOT NULL,
    platform TEXT,
    os_version TEXT,
    ip_address TEXT,
    mac_address TEXT,
    owner TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('unknown', 'online', 'offline', 'isolated', 'retired')),
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE TABLE IF NOT EXISTS processes (
    process_record_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    event_id TEXT,
    process_id INTEGER NOT NULL,
    parent_process_id INTEGER,
    image_name TEXT NOT NULL,
    image_path TEXT,
    command_line TEXT,
    user_name TEXT,
    integrity_level TEXT,
    hash_sha256 TEXT,
    started_at_utc TEXT NOT NULL,
    ended_at_utc TEXT,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'terminated', 'unknown')),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (event_id) REFERENCES sensor_events(event_id)
);

CREATE TABLE IF NOT EXISTS connections (
    connection_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    process_record_id TEXT,
    event_id TEXT,
    protocol TEXT NOT NULL,
    local_address TEXT,
    local_port INTEGER,
    remote_address TEXT,
    remote_port INTEGER,
    remote_hostname TEXT,
    direction TEXT NOT NULL DEFAULT 'unknown'
        CHECK (direction IN ('inbound', 'outbound', 'local', 'unknown')),
    state TEXT,
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (process_record_id) REFERENCES processes(process_record_id),
    FOREIGN KEY (event_id) REFERENCES sensor_events(event_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    finding_id TEXT UNIQUE,
    device_id TEXT NOT NULL,
    event_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'triaged', 'in_progress', 'resolved', 'dismissed')),
    provider_id TEXT,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    resolved_at_utc TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (event_id) REFERENCES sensor_events(event_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT,
    severity TEXT NOT NULL
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    owner TEXT,
    opened_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    closed_at_utc TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    linked_at_utc TEXT NOT NULL,
    PRIMARY KEY (incident_id, alert_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);

CREATE TABLE IF NOT EXISTS mitre_mappings (
    mapping_id TEXT PRIMARY KEY,
    alert_id TEXT,
    finding_id TEXT,
    technique_id TEXT NOT NULL,
    tactic TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium'
        CHECK (confidence IN ('low', 'medium', 'high')),
    source TEXT NOT NULL DEFAULT 'engine',
    created_at_utc TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(technique_id),
    CHECK (alert_id IS NOT NULL OR finding_id IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    incident_id TEXT,
    device_id TEXT,
    alert_id TEXT,
    report_type TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'generated', 'reviewed', 'exported', 'archived')),
    body TEXT NOT NULL,
    generated_by TEXT,
    generated_at_utc TEXT NOT NULL,
    exported_path TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);

CREATE INDEX IF NOT EXISTS idx_devices_hostname
    ON devices(hostname);

CREATE INDEX IF NOT EXISTS idx_devices_status_risk
    ON devices(status, risk_score);

CREATE INDEX IF NOT EXISTS idx_processes_device_pid
    ON processes(device_id, process_id);

CREATE INDEX IF NOT EXISTS idx_processes_started
    ON processes(started_at_utc);

CREATE INDEX IF NOT EXISTS idx_connections_device_remote
    ON connections(device_id, remote_address, remote_port);

CREATE INDEX IF NOT EXISTS idx_connections_seen
    ON connections(first_seen_utc, last_seen_utc);

CREATE INDEX IF NOT EXISTS idx_alerts_device_status
    ON alerts(device_id, status);

CREATE INDEX IF NOT EXISTS idx_alerts_severity_created
    ON alerts(severity, created_at_utc);

CREATE INDEX IF NOT EXISTS idx_incidents_status_severity
    ON incidents(status, severity);

CREATE INDEX IF NOT EXISTS idx_mitre_mappings_technique
    ON mitre_mappings(technique_id);

CREATE INDEX IF NOT EXISTS idx_reports_subjects
    ON reports(incident_id, device_id, alert_id);
