# TRUSTRAIL AI P0 System Architecture

**Status:** Current-state architecture with the approved backend
report-snapshot service and investigation-page integration implemented. The
PDF renderer is unchanged.

## Current system

```text
Authorized local telemetry
        |
        v
src/trustrail_pipeline
  local parsing, normalization, provenance, graph-ready exports
        |
        v
member2_graph importer / validator
        |
        v
Neo4j GraphNode records <---- backend/app/database/Neo4jConnection
        |                                  |
        |                                  v
        |                         FastAPI backend/app
        |                           |      |       |
        |                           |      |       +-- Member 4 in-process model adapter
        |                           |      +---------- existing investigation/incident services
        |                           +----------------- graph, threat, dashboard, simulation APIs
        |
        +--------------------------> React frontend (Member B-owned)
```

The actual active graph API is the FastAPI implementation under
`backend/app/services/graph_service.py` and `backend/app/routes/graph.py`.
`member2_graph/src/graph_service.py` is a separate legacy helper and is not
the application route/service implementation. Do not mount it as a second
backend.

Member 3's current pipeline reads local CSV, JSON, or JSONL input and exports
normalized graph records. It does not call AbuseIPDB, OTX, NVD, CISA KEV, OSV,
Wazuh, or another external threat-intelligence API.

The backend creates one `Member4DetectionEngine` and invokes Member 4's
bundled predictor and deterministic investigation-priority scorer in-process.
The separate `member4_ml/src/api.py` is not used by the backend. The backend
does not call Ollama or another LLM service. The model's explanations are
not a validated LLM explanation service.

## Existing service boundaries

| Boundary | Current owner / implementation | Current behavior |
|---|---|---|
| Local ingestion and normalization | `src/trustrail_pipeline` | Validates and normalizes local records while preserving provenance. |
| Graph import | `member2_graph/importer.py` | Validates JSONL and writes the graph using the existing import contract. |
| Neo4j access | `backend/app/database/neo4j_connection.py` | Shared driver, parameterized read/write transactions, bounded timeout, explicit connection errors. |
| Graph query API | `backend/app/services/graph_service.py` | Entity, neighborhood, subgraph, path, and overview queries with bounds. |
| Threat inference | `backend/app/services/threat_service.py` and `member4_detection.py` | Reads stored events and invokes the existing Member 4 model/scorer on demand. |
| Investigation records | `backend/app/services/investigation_service.py` | Creates and stores investigation metadata, status, notes, evidence references, and audit history. |
| Report snapshot assembly and persistence | `backend/app/services/report_data_service.py` | Captures investigation, bounded graph/evidence, and Member 4 event assessment data into an immutable stored payload. |
| Authentication | Middleware in `backend/app/main.py` | Optional in development; shared bearer token required at production startup. |
| Report rendering/delivery | Member B | The investigation page captures and displays snapshots through the authenticated routes; PDF rendering remains Member B-owned. |

## Existing investigation lifecycle

The current API persists investigation records as
`GraphNode:Entity` nodes with `type: "Investigation"`. The current states are
`OPEN`, `IN_PROGRESS`, and `CLOSED`. An investigation contains its title,
optional related event ID, linked entity IDs, timestamps, notes, evidence IDs,
and audit history.

Creating an investigation does not currently run a combined workflow. It
does not automatically retrieve graph evidence, call an external
intelligence provider, assemble a Member 4 assessment, or call an AI
explanation service. Attack paths are requested separately and on demand;
they are not persisted. Consequently, the current `OPEN` record is a
workflow record, not a completed investigation assessment.

## P0 target boundary

The intended backend orchestration should reuse the existing services rather
than introduce a second graph client, risk engine, intelligence client, or
backend:

1. Validate/authenticate the existing investigation request.
2. Record a traceable investigation identifier and initial state.
3. Use the existing graph service for actual graph evidence.
4. Call an existing Member 3 provider service only if one is verified and
   available; otherwise represent that section as unavailable.
5. Use Member 4's existing risk function without changing its formula.
6. Call an AI explanation service only if one exists and is validated;
   otherwise return AI-unavailable.
7. Validate and assemble partial results without converting missing evidence
   into negative findings or default low risk.
8. Produce a report-data snapshot from actual stored investigation data.
9. Persist the snapshot immutably in Neo4j as a `ReportSnapshot` node that is
   separate from the operational graph.
10. Expose create/retrieval through the existing authenticated backend
    boundary.

The approved top-level `InvestigationReportSnapshot` fields, nested types,
section states, routes, and error mappings are documented in
`P0_API_CONTRACTS.md`.

The report snapshot service reuses `InvestigationService`, `GraphService`, and
`ThreatService.analyze_event()`. It persists the validated serialized payload,
and retrieval does not re-run analysis. External threat intelligence and AI
explanations are represented as `not_implemented`; unavailable model
assessments retain graph/evidence while returning a partial snapshot with no
invented score.

## Trust and data boundaries

- Neo4j and provider/model outputs are untrusted input.
- Cypher remains parameterized and supplied by backend code, never by the
  frontend.
- Graph connectivity and attack paths mean potential relationships/exposure;
  they do not prove malicious activity or attacker traversal.
- Member 4's prediction and investigation-priority score are analyst signals,
  not proof or a probability of compromise.
- Source `evidence_status` must remain distinct from model-generated
  `evidence_status`.
- Synthetic fixture records and in-memory demo workflow writes must remain
  labeled synthetic and must not be presented as real evidence.
- The production shared bearer token does not establish a user's identity,
  role, or investigation ownership.

## Dependency and failure behavior

Neo4j is the only currently configured external runtime dependency of the
backend. A missing/unavailable database is reported through `/api/health` and
database errors map to service-unavailable responses. `/healthz` is process
liveness only. There is no `/api/ready` endpoint and no current readiness
report for model, threat-intelligence, or AI services.

Member 4's model is local/in-process. Missing model artifacts/dependencies map
to an unavailable-service error; inference and malformed-event failures are
reported separately. No external provider or Ollama timeout/fallback path
exists because those clients are not implemented.

## Security and operations

Production requires `API_BEARER_TOKEN`; configured API routes use the shared
token middleware. Per-user authorization and ownership are not implemented.
Neo4j access is parameterized and query depth/limits are bounded. CORS is
configurable. There is no general rate limiter, global request-size limit,
request correlation ID, or structured per-operation duration logging.

The Render configuration probes `/healthz`, so deployment liveness can be
healthy while Neo4j is unavailable. Before a live demonstration, verify
`/api/health` and run authorized graph/import checks using rotated credentials.

## Verification state

See `P0_REPOSITORY_AUDIT.md` for current test commands and results. Tests
cover mocked services and local synthetic fixtures, including snapshot
creation, retrieval, model-failure fallback, and bearer-token protection.
Live Neo4j, external intelligence, Ollama, and frontend build behavior remain
unverified.
