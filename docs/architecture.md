# Hybrid EDR Architecture

## Component Boundaries

### C++ Sensor Module

Owns endpoint-side telemetry collection and local buffering.

Responsibilities:

- Collect endpoint telemetry from platform-specific collectors.
- Normalize raw observations into shared event contracts.
- Send events to the Python detection engine through a transport adapter.
- Avoid detection decisions.

Non-responsibilities:

- Threat scoring.
- MITRE ATT&CK mapping.
- AI report generation.
- Dashboard presentation.

### Python Detection Engine

Owns event ingestion orchestration, detection interface execution, enrichment, scoring coordination, persistence coordination, and report orchestration.

Responsibilities:

- Receive normalized sensor events.
- Validate event schema.
- Route events through pluggable detection providers.
- Coordinate future MITRE ATT&CK mapping.
- Coordinate future threat intelligence enrichment.
- Persist events, alerts, findings, and reports through repository interfaces.
- Expose read APIs for the dashboard.

Non-responsibilities:

- Endpoint collection.
- Direct UI rendering.
- SQLite schema ownership.

### SQLite Database

Owns durable local storage.

Responsibilities:

- Store sensor events, assets, alerts, findings, MITRE mappings, threat intelligence records, and AI report metadata.
- Keep migrations versioned.
- Avoid embedding application logic in SQL beyond constraints and indexes.

### CustomTkinter Dashboard

Owns local operator experience.

Responsibilities:

- Display assets, events, alerts, reports, and system status.
- Call application services or API clients instead of querying SQLite directly.
- Keep presentation logic separate from detection and persistence logic.

## Data Flow

```text
C++ Collectors
    -> Sensor Event Normalizer
    -> Sensor Transport
    -> Python Ingestion Port
    -> Event Router
    -> Detection Provider Interfaces
    -> Enrichment Interfaces
    -> Repository Interfaces
    -> SQLite
    -> Dashboard Services
    -> CustomTkinter Views
```

## Extension Points

### MITRE ATT&CK

Add technique mapping after event validation and before alert persistence.

Primary interfaces:

- `MitreMapper`
- `TechniqueCatalog`
- `AlertTechniqueRepository`

### Threat Intelligence

Add enrichment after an event or alert contains observables.

Primary interfaces:

- `ThreatIntelProvider`
- `ObservableExtractor`
- `ThreatIntelRepository`

### AI Reports

Add report generation from persisted case, alert, and timeline data.

Primary interfaces:

- `ReportGenerator`
- `ReportRepository`
- `ReportTemplateProvider`

## Dependency Rule

Outer layers may depend inward on contracts, but core orchestration must not depend directly on UI widgets, database drivers, or sensor implementation details.

Recommended direction:

```text
dashboard -> detection_engine.services -> detection_engine.core -> shared
database.adapters -> database.contracts -> shared
sensor_cpp.adapters -> shared
```
