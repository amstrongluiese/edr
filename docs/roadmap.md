# Implementation Roadmap

## Phase 1: Architecture Foundation

- Finalize shared event schemas.
- Define C++ sensor interfaces.
- Define Python ingestion, detection, persistence, enrichment, and reporting interfaces.
- Create SQLite migration layout.
- Create CustomTkinter dashboard shell boundaries.

Deliverable:

- Components compile or import without runtime detection behavior.

## Phase 2: Sensor Pipeline

- Implement platform-specific C++ collectors.
- Implement local event normalization.
- Implement sensor-to-engine transport.
- Add backpressure and buffering strategy.
- Add integration tests using synthetic telemetry.

Deliverable:

- Sensor can send valid normalized events to the engine.

## Phase 3: Detection Engine Core

- Implement event validation.
- Implement detection provider loading.
- Implement alert lifecycle services.
- Implement repository adapters for SQLite.
- Add structured logging and error handling.

Deliverable:

- Engine can ingest events, invoke empty providers, and persist records.

## Phase 4: Dashboard MVP

- Build CustomTkinter navigation shell.
- Add views for system status, assets, events, alerts, and reports.
- Add dashboard service layer.
- Add polling or event subscription strategy.

Deliverable:

- Operator can inspect stored telemetry and placeholder alert/report records.

## Phase 5: MITRE ATT&CK Support

- Add local technique catalog model.
- Add mapping interface implementation.
- Store alert-to-technique relationships.
- Add ATT&CK coverage views in the dashboard.

Deliverable:

- Alerts can be associated with tactics and techniques.

## Phase 6: Threat Intelligence Support

- Add observable extraction.
- Add provider abstraction for local and remote intel sources.
- Cache enrichment results.
- Add reputation and enrichment views.

Deliverable:

- Events and alerts can be enriched with external or local intelligence.

## Phase 7: AI Reports

- Add report templates.
- Add report generation orchestration.
- Add report history and export metadata.
- Add dashboard report viewer.

Deliverable:

- Analysts can generate structured investigation summaries from persisted data.

## Phase 8: Hardening

- Add authentication and authorization if multi-user access is introduced.
- Add tamper resistance for local database and logs.
- Add upgrade and migration tests.
- Add packaging for sensor, engine, and dashboard.

Deliverable:

- System is ready for controlled pilot deployment.
