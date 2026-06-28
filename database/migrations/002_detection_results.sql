CREATE TABLE IF NOT EXISTS risk_assessments (
    risk_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES sensor_events(event_id),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE INDEX IF NOT EXISTS idx_sensor_events_asset_time
    ON sensor_events(asset_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_findings_event
    ON findings(event_id);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_asset
    ON risk_assessments(asset_id, score);
