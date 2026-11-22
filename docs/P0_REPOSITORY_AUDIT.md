# TRUSTRAIL AI P0 Repository Audit

**Audit date:** 2026-11-22  
**Scope:** Existing backend, graph, data pipeline, Member 4 model integration,
security, tests, and deployment. The investigation page now consumes the
report-snapshot API; the PDF renderer is unchanged. The worktree contained a
staged merge, which was preserved until the user approved including all
current work in the publish.

## Executive summary

The repository has a working FastAPI application with parameterized Neo4j
queries, bounded graph traversal, investigation and incident CRUD workflows,
and an in-process adapter to Member 4's bundled detector and investigation
priority scorer. Automated backend, graph, and data-pipeline tests pass.

The repository now has an authenticated report-snapshot service that captures
existing investigation data, bounded graph/evidence results, and Member 4's
assessment for a linked event. It persists a validated payload and can return
that immutable capture without re-running analysis. This does not make the
investigation CRUD workflow a full automated investigation: external
threat-intelligence providers and an AI explanation service are still not
implemented, and live Neo4j behavior and frontend consumption remain
unverified.

The audit is based on source and synthetic fixtures. Live Neo4j behavior and
the frontend build were not verified. A Neo4j credential was exposed in the
conversation; it must be rotated before any live connection test. The secret
is intentionally not recorded here.

## Architecture and evidence

1. The application entry point is [`backend/app/main.py`](../backend/app/main.py).
   It creates one FastAPI app, shared Neo4j connection, and in-process
   `Member4DetectionEngine`; it mounts dashboard, graph, threat, incident,
   investigation, blast-radius, and containment routers.
2. Neo4j connection and transaction management are in
   [`backend/app/database/neo4j_connection.py`](../backend/app/database/neo4j_connection.py).
   Driver sessions are scoped, reads/writes run in worker threads, connection
   timeout is 10 seconds, and query transactions use a configurable timeout.
   Queries are defined in
   [`backend/app/database/queries.py`](../backend/app/database/queries.py)
   and use parameters rather than user-supplied Cypher.
3. Active graph API logic is in
   [`backend/app/services/graph_service.py`](../backend/app/services/graph_service.py),
   not the legacy helper under `member2_graph/src`. The active routes are in
   [`backend/app/routes/graph.py`](../backend/app/routes/graph.py) and the
   attack-path query is reused by investigations.
4. Member 3's local-file normalizer is under
   [`src/trustrail_pipeline`](../src/trustrail_pipeline). It accepts local CSV,
   JSON, or JSONL input and exports graph-ready records. Member 2's
   [`member2_graph/importer.py`](../member2_graph/importer.py) validates and
   imports those records. Neither component is an external threat-intelligence
   provider client.
5. Backend threat analysis is performed by
   [`backend/app/services/member4_detection.py`](../backend/app/services/member4_detection.py),
   which loads Member 4's bundled artifacts and calls the existing prediction
   and investigation-priority functions. The separate
   [`member4_ml/src/api.py`](../member4_ml/src/api.py) inference API is not the
   backend runtime path.
6. Deployment is configured by [`render.yaml`](../render.yaml). It uses the
   public `/healthz` liveness route; this does not verify Neo4j readiness.

## Subsystem status

| Subsystem | Status | Evidence and limitations |
|---|---|---|
| FastAPI app and existing routes | **WORKING** | Routes are mounted in `main.py`; request/response behavior is covered by backend tests. |
| Shared bearer authentication | **PARTIALLY WORKING** | Configured bearer token is compared in middleware and required at production startup. It is a shared token, not an analyst identity, role system, or per-investigation authorization model. In development, an empty token leaves API routes unauthenticated. |
| CORS | **PARTIALLY WORKING** | Origins are configured from `CORS_ORIGINS`; exact deployed values and browser behavior are not live-verified. |
| Neo4j query and connection layer | **PARTIALLY WORKING** | Parameterized queries, bounded transactions, driver lifecycle, and mocked error handling are tested. No live Neo4j connection, schema, constraints, or query behavior was verified. |
| Graph queries and attack paths | **PARTIALLY WORKING** | Entity, neighborhood, subgraph, blast-radius, and directed path queries exist with depth/result bounds. Tests use mocks or fixture behavior; live graph IDs and records remain unverified. |
| Synthetic development adapter | **PARTIALLY WORKING** | A bundled graph fixture adapter is present. It is now selected only when all Neo4j credentials are empty; partial credentials produce an explicit configuration error. Its investigation and snapshot writes are in-memory and lost on restart. |
| Member 3 ingestion/normalization | **WORKING for local-file ingestion** | Pipeline handles local files, provenance, validation, and graph-ready exports. It does not call external reputation or vulnerability services. |
| External threat-intelligence providers | **MISSING** | No provider client, API-key configuration, provider timeout/cache/rate-limit handling, or normalized provider-result endpoint was found. Documentation also states these providers are not queried. |
| Member 4 detector integration | **PARTIALLY WORKING** | Backend adapter invokes the existing local model and scorer; backend tests exercise it. The model was evaluated on small synthetic data, so real-world detection quality is unverified. |
| Graph-aware risk scoring | **PARTIALLY WORKING** | Member 4 has graph feature extraction and a graph-context score component. The backend does not fetch/pass graph context to the scorer; its limitations explicitly state that graph context is excluded. No new scoring formula should be introduced here. |
| Evidence-grounded AI/Ollama | **MISSING** | No Ollama client/configuration or LLM explanation service was found. Member 4's existing feature-based explanation is not an Ollama integration and does not provide a separately validated evidence-citation contract. |
| Investigation orchestration | **PARTIALLY WORKING** | `POST /api/investigations`, list/detail, notes, evidence, status, timeline, and investigation-scoped attack paths exist. Creation writes an `OPEN` record and links supplied IDs; it does not orchestrate graph, intelligence, risk, or AI services or transition through `RUNNING/PARTIAL/FAILED`. |
| Investigation persistence/history | **PARTIALLY WORKING** | Investigation records and audit entries are stored on `GraphNode:Entity`; listing is paginated. Report snapshots are stored separately as `ReportSnapshot` nodes. There is no processing recovery state, owner identity, or create-request idempotency. Synthetic adapter writes remain in-memory and are lost on process restart. |
| Report-data snapshot service | **IMPLEMENTED; LIVE DB UNVERIFIED** | `ReportDataService` assembles a typed snapshot from existing investigation, graph, evidence, and Member 4 services. Authenticated create/retrieval routes persist and return immutable JSON payloads; unit tests cover partial fallback and bounded data. Live Neo4j execution and Member B rendering are not verified. |
| Health/readiness | **PARTIALLY WORKING** | `/healthz` is process liveness and `/api/health` reports Neo4j health. `/api/ready` and dependency-by-dependency diagnostics are missing; Member 4 and optional-service readiness are not reported. |
| Logging/observability | **PARTIALLY WORKING** | Neo4j/model failures use Python logging with limited error categories. Request IDs, investigation correlation, structured operation timing, and audit-level observability are not implemented. |
| Rate/body-size limits | **MISSING** | Route-level Pydantic bounds exist for several fields and queries, but there is no general request-size limit or rate limiter. |
| Frontend/PDF contract | **PARTIALLY INTEGRATED; BUILD UNVERIFIED** | The investigation page can capture, display, and reload report snapshots through the backend API. The PDF renderer remains unchanged. Node/npm are unavailable, so frontend build/browser verification and live backend consumption remain pending. |
| Deployment | **PARTIALLY WORKING** | Render configuration, environment variables, bearer-token requirement, and liveness probe exist. Database readiness, live deployment settings, and production end-to-end behavior are unverified. |

## Existing investigation contract

The current request model is
[`backend/app/schemas/investigation_schema.py`](../backend/app/schemas/investigation_schema.py):

- Create: `title`, optional `alert_id`, and up to 50 `entity_ids`.
- Notes: required `content` with a 10,000-character limit.
- Evidence attachment: required `evidence_id`.
- Status values: `OPEN`, `IN_PROGRESS`, `CLOSED`.

The service in
[`backend/app/services/investigation_service.py`](../backend/app/services/investigation_service.py)
creates an `INV-<uuid>` identifier, records timestamps and an audit entry,
validates referenced alerts/entities through the existing write query, and
stores investigation metadata on a graph entity. Evidence attachment avoids
duplicate evidence IDs; status changes use an expected-current-status check.
Audit actor is the constant `backend_api`, not an authenticated user.

The existing attack-path operation is on demand and validates that both
distinct endpoints are linked to the investigation. It returns potential
connectivity and explicitly does not establish attacker traversal. It does
not persist a path snapshot.

## Security and reliability findings

### Immediate

- Rotate the Neo4j password exposed in the conversation, update the local
  environment privately, and do not include credentials in documentation,
  logs, source control, or chat. This audit did not use that credential.
- Preserve the shared-token limitation: it cannot support per-user
  ownership or role-based access. Do not add owner/current-user fields until
  the project owner approves an identity model.
- The partial-Neo4j-credentials fallback issue has been fixed and covered by
  an application-construction test. The synthetic adapter remains an
  in-memory development/test store, not persistent Neo4j.

### Before P0 end-to-end use

- Agree with Member B on the report-data interface and persistence/snapshot
  approach before implementing it. The backend owns assembly and validation;
  PDF rendering/download remains Member B's responsibility.
- Agree with Members 3 and 4 on service availability and input/output
  contracts. At present, no external-intelligence service or Ollama service
  can be called by this backend.
- The snapshot route is not an investigation job runner. Agree whether a
  separate orchestration lifecycle and recovery strategy are required without
  replacing the existing CRUD or duplicating other members' logic.
- Add `/api/ready` separately from liveness, with required dependencies
  distinguished from optional services.
- Add request-size/rate controls and correlation/timing logs as approved,
  avoiding sensitive event text and credentials in logs.
- Verify actual Neo4j schema and representative records only after credentials
  are rotated and authorized infrastructure is reachable.

## Environment and dependencies

Backend settings are read in
[`backend/app/config.py`](../backend/app/config.py):

- `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`
- `CORS_ORIGINS`, `MAX_GRAPH_DEPTH`, `NEO4J_QUERY_TIMEOUT_SECONDS`
- `API_BEARER_TOKEN`, `APP_ENV`, `DEMO_FALLBACK`

The backend requirements include FastAPI, Uvicorn, Neo4j driver, Pydantic,
python-dotenv, test dependencies, and Member 4's requirements. No external
threat-intelligence or Ollama dependency is configured. Render sets
`APP_ENV=production`, requires the bearer token and Neo4j variables, and
probes `/healthz`.

## Verification performed

All commands below use mocked or synthetic data; none contacted Neo4j or an
external provider.

| Command | Result |
|---|---|
| `python -m unittest discover -s backend\tests -v` | **70 passed** |
| `$env:PYTHONPATH='member2_graph'; python -m unittest discover -s member2_graph\tests -v` | **19 passed** |
| `python -m unittest discover -s tests -v` | **19 passed** |
| `$env:PYTHONPATH='member2_graph'; python member2_graph\validate.py --fixture data\graph_fixture` | **Passed**: 18 entities, 17 events, 17 evidence records, 68 relationships, 0 rejected lines |
| `python -m compileall -q backend\app backend\tests` | **Passed** |
| `git diff --check` and `git diff --cached --check` | **Passed** |

The standalone Member 4 runner expects
`data/demo-run/processed/events.jsonl`; that file is absent. It was not
fabricated or silently substituted. The backend's bundled-model tests pass,
but the standalone runner remains blocked pending Member 4's approved fixture
or test-contract decision.

Node/npm are unavailable, so frontend build/tests were not run. The local
Neo4j Bolt port was not available, and no live query/import, live report
snapshot, performance measurement, or external provider test was performed.

## Prioritized next steps

1. Rotate the exposed Neo4j password; verify `.env` remains untracked.
2. Verify report snapshot creation/retrieval against an authorized live Neo4j
   instance and confirm Member B consumes the documented payload.
3. Coordinate available threat/risk/AI interfaces with Members 3 and 4.
4. Decide whether broader investigation orchestration is required beyond the
   current snapshot service; retain the existing service ownership boundaries.
5. Add readiness and approved security/reliability controls.
6. Test with rotated, authorized Neo4j credentials and real project-owned
   records; keep synthetic and real results distinguishable.
7. Ask Member B to run the frontend build and browser integration tests; do
   not claim frontend completion until these pass.
8. Complete review and commit of the existing staged merge only after its
   owner approves the full staged file set.
