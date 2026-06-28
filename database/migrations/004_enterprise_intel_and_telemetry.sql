-- Enterprise telemetry and threat intelligence extension.

CREATE TABLE IF NOT EXISTS dns_logs (
    dns_log_id TEXT PRIMARY KEY,
    event_id TEXT UNIQUE,
    device_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    query TEXT NOT NULL,
    answer TEXT,
    record_type TEXT,
    response_code TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (event_id) REFERENCES sensor_events(event_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    traffic_log_id TEXT PRIMARY KEY,
    event_id TEXT UNIQUE,
    device_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    source_address TEXT,
    source_port INTEGER,
    destination_address TEXT,
    destination_port INTEGER,
    protocol TEXT,
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    direction TEXT NOT NULL DEFAULT 'unknown'
        CHECK (direction IN ('inbound', 'outbound', 'local', 'unknown')),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (event_id) REFERENCES sensor_events(event_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS validation_results (
    result_id TEXT PRIMARY KEY,
    test_name TEXT NOT NULL,
    expected_result TEXT NOT NULL,
    actual_result TEXT NOT NULL,
    pass_fail TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intelligence (
    indicator_id TEXT PRIMARY KEY,
    observable_value TEXT NOT NULL,
    observable_kind TEXT NOT NULL,
    source TEXT NOT NULL,
    reputation TEXT NOT NULL
        CHECK (reputation IN ('benign', 'unknown', 'suspicious', 'malicious')),
    confidence INTEGER NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    summary TEXT,
    cve_id TEXT,
    cve_severity TEXT
        CHECK (cve_severity IS NULL OR cve_severity IN ('low', 'medium', 'high', 'critical')),
    first_seen_utc TEXT,
    last_seen_utc TEXT,
    expires_at_utc TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    UNIQUE (observable_kind, observable_value, source)
);

CREATE TABLE IF NOT EXISTS threat_intel_matches (
    match_id TEXT PRIMARY KEY,
    event_id TEXT,
    alert_id TEXT,
    indicator_id TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    observable_kind TEXT NOT NULL,
    source TEXT NOT NULL,
    reputation TEXT NOT NULL,
    risk_points INTEGER NOT NULL DEFAULT 0,
    matched_at_utc TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (event_id) REFERENCES sensor_events(event_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
    FOREIGN KEY (indicator_id) REFERENCES threat_intelligence(indicator_id)
);

CREATE INDEX IF NOT EXISTS idx_dns_logs_device_time
    ON dns_logs(device_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_device_time
    ON traffic_logs(device_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_threat_intelligence_lookup
    ON threat_intelligence(observable_kind, observable_value, reputation);

CREATE INDEX IF NOT EXISTS idx_threat_intel_matches_event
    ON threat_intel_matches(event_id);

