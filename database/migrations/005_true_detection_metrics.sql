-- Phase 5.5 evidence-based detection evaluation metrics.

CREATE TABLE IF NOT EXISTS validation_metrics (
    metric_id TEXT PRIMARY KEY,
    result_id TEXT,
    test_name TEXT NOT NULL,
    expected_positive INTEGER NOT NULL CHECK (expected_positive IN (0, 1)),
    detected_positive INTEGER NOT NULL CHECK (detected_positive IN (0, 1)),
    true_positive INTEGER NOT NULL DEFAULT 0,
    true_negative INTEGER NOT NULL DEFAULT 0,
    false_positive INTEGER NOT NULL DEFAULT 0,
    false_negative INTEGER NOT NULL DEFAULT 0,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    cpu_usage_percent REAL NOT NULL DEFAULT 0,
    memory_usage_mb REAL NOT NULL DEFAULT 0,
    ioc_matches INTEGER NOT NULL DEFAULT 0,
    cve_matches INTEGER NOT NULL DEFAULT 0,
    created_at_utc TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_validation_metrics_created
    ON validation_metrics(created_at_utc);

