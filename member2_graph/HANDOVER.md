# Neo4j Graph Intelligence Audit and Handover

**Status snapshot:** 2026-11-22
**Scope:** Repository implementation and synthetic fixture. No live Neo4j
database was available for inspection or testing.

## Executive summary

The active application uses the backend-owned Neo4j connection and FastAPI
graph routes. Member 3's current pipeline produces graph-ready JSONL; the
Member 2 importer validates and writes those files. The backend exposes
bounded graph queries, including an investigation-scoped, on-demand attack
path endpoint.

This is not yet a complete external-intelligence-to-AI integration. No
provider connector or direct external-intelligence ingestion API was found in
the repository. Member 4's graph feature extractor accepts graph context, but
the backend does not populate it from Neo4j. Aura connectivity, live imports,
live attack-path queries, frontend build verification, and performance tests
remain pending.

## Audited architecture

1. `src/trustrail_pipeline/graph_csv.py` exports validated records to JSONL.
2. `member2_graph/importer.py` validates the files and imports them using the
   official Neo4j Python driver, parameterized Cypher, `MERGE`, and batched
   write transactions.
3. `backend/app/database/neo4j_connection.py` owns the reusable backend
   driver, health check, and read/write transaction wrapper.
4. `backend/app/services/graph_service.py` and
   `backend/app/routes/graph.py` provide the active graph query API.
5. `backend/app/services/investigation_service.py` reuses that graph service
   for investigation-scoped attack paths. The frontend calls this through
   `frontend/src/services/api.js`.

There is also a separate helper implementation under
`member2_graph/src/`. It is not mounted in the FastAPI application and should
not be used to create duplicate backend routes. The two graph services are
not interchangeable: use the backend service for the running application.

## Current graph contract

| Record | Labels | Stable key | Properties represented by the current contract |
|---|---|---|---|
| Entity | `GraphNode:Entity` | `id` | Required `type`, `synthetic`; optional `name`, `criticality` |
| Security event | `GraphNode:SecurityEvent` | shared `id` and `event_id` | Event type/time, severity, description, evidence ID, synthetic flag, and available source/time provenance |
| Evidence | `GraphNode:Evidence` | shared `id` and `evidence_id` | Event/source IDs, source system, observation time, evidence status, synthetic flag, and available provenance |

Entity types are values of `Entity.type`, not dedicated labels in this
contract. Incident and investigation records also use `GraphNode:Entity` with
their own `type` and workflow properties.

| Relationship | Direction | Category |
|---|---|---|
| `AUTHENTICATED_TO`, `COMMUNICATES_WITH`, `RUNS`, `DEPENDS_ON`, `HAS_VULNERABILITY`, `INVOLVES` | Entity → Entity | `original_entity` |
| `SUPPORTED_BY` | SecurityEvent → Evidence | `event_trace` |
| `OBSERVED_ON` | SecurityEvent → Entity | `event_trace`; requires `endpoint_role` |

Relationship records retain `relationship_id`, direction, evidence status,
event association where supplied, and synthetic provenance. The importer
validates endpoint types for domain relationships against
[`ingestion_contract.md`](../docs/ingestion_contract.md).

### Constraints and indexes

The importer creates a uniqueness constraint on `GraphNode.id`:

```cypher
CREATE CONSTRAINT graph_node_id IF NOT EXISTS
FOR (n:GraphNode) REQUIRE n.id IS UNIQUE;
```

This is the only explicit graph constraint/index definition found in the
active importer. No additional indexes are currently defined. The live
database's constraints and indexes have not been verified.

## Ingestion and provenance

Current offline path:

```powershell
$env:PYTHONPATH = "src"
python -m trustrail_pipeline.cli ingest-graph --entities <entities.csv> --relationships <relationships.csv> --events <events.csv> --evidence <evidence.csv> --output-dir data\graph_fixture

$env:PYTHONPATH = "member2_graph"
python member2_graph\validate.py --fixture data\graph_fixture
python member2_graph\importer.py --input-dir data\graph_fixture --batch-size 500
```

The importer requires entity, event, evidence, and relationship JSONL files.
It rejects malformed records, empty stable identifiers, invalid relationship
roles, and duplicate node or relationship identifiers before writing. Node
and relationship `MERGE` keys make repeated imports with stable IDs
idempotent by design; this has **not** been confirmed by repeated imports
against live Neo4j. Failed batches are reported and rolled back by their
transaction. Import statistics report records read/imported and failures;
they do not distinguish created nodes from updated nodes.

The current contract retains source fields where the exporter supplies them,
especially for events and evidence. It does not implement provider-specific
observation history, conflict resolution, freshness/expiry rules, or a
quality-aware merge policy. The importer preserves supplied non-null values;
it cannot determine whether a new provider value is more reliable than an
existing value.

No AbuseIPDB, OTX, NVD, CISA KEV, OSV, or other external provider connector
was found in the repository. The current ingestion boundary is the validated
Member 3 JSONL export, not a provider API or a secured backend ingestion route.

## Query and application interfaces

The active backend includes graph overview, entity listing/detail, neighbors,
relationships, subgraph, attack paths, blast-radius analysis, and
investigation operations. In production, backend routes require the
configured bearer token, except the documented health endpoints.

The investigation path endpoint is:

```text
GET /api/investigations/{investigation_id}/attack-paths
    ?source_id=<linked-entity-id>&target_id=<linked-entity-id>
    &depth=3&limit=20
```

Both distinct endpoints must be linked to the investigation. The service
reuses the existing backend attack-path query and does not persist results.
Traversal is directed, restricted to `Entity` nodes and
`original_entity` relationships, bounded by configured depth and result limit.
Results indicate possible graph connectivity, not attacker traversal. The
query orders by path length but does not implement a broader explainable
ranking strategy or attach separate event/evidence records to each path.

Graph list queries are paginated and traversal routes apply limits. The
backend driver configures a 10-second connection timeout and a configurable
transaction timeout (30 seconds by default, 1–120 seconds). The live
database's behavior under timeout has not been tested. The importer uses a
configurable positive batch size and the default is 500.

## Security and integration boundaries

- Database credentials are read from environment configuration; no user or
  model-supplied Cypher is accepted by the graph routes.
- Backend graph query values are parameterized. Attack-path depth is
  interpolated only after integer bounds are enforced. The importer
  interpolates relationship types only from its fixed allowlist.
- Production API bearer-token enforcement is implemented in the backend.
- A least-privilege Neo4j role has not been configured or verified here.
- No graph ingestion HTTP route is exposed. Members should not bypass the
  central backend's authentication/orchestration ownership.
- Reachability and attack paths are exposure context, not proof of
  compromise. `HAS_VULNERABILITY` is an available relationship type, but no
  asset-version/CVE validation or live vulnerability-feed mapping is
  implemented.

### Handoff

- **Member 3:** Export the agreed entity/event/evidence/relationship JSONL
  contract, run offline validation, and hand the files to the importer.
  Provider connectors and provider-specific observation storage remain
  separate work; do not write Cypher in the exporter.
- **Member 4:** `member4_ml/src/graph_features.py` defines graph-derived
  feature extraction from a supplied context. The backend currently does not
  fetch and pass that context; its inference response explicitly notes that
  graph context is excluded from investigation priority. Agree on fields and
  evidence semantics before wiring it in; do not treat graph paths or
  vulnerability matches as observed attacks.
- **Member 5:** Keep the existing backend as the route/authentication owner.
  Use the backend `GraphService` and investigation-scoped endpoint; do not
  mount the standalone `member2_graph/src/graph_service.py` as a second API.

## Evidence and completion status

| Capability | Status | Evidence / limitation |
|---|---|---|
| Repository graph schema and route audit | **PARTIALLY IMPLEMENTED** | Code inspection is complete; the deployed Aura schema and external team contracts could not be inspected or confirmed. |
| Reusable Neo4j backend connection, health check, and transaction timeout | **IMPLEMENTED BUT NOT FULLY TESTED** | Driver lifecycle, health behavior, and configured timeout propagation have unit coverage; no live Aura recovery or authentication test was run. |
| Synthetic JSONL fixture validation | **FULLY IMPLEMENTED AND TESTED** | Offline fixture validation passes and checks IDs, structure, endpoint types, and relationship direction. |
| JSONL ingestion for current contract | **IMPLEMENTED BUT NOT FULLY TESTED** | Importer code and mocked compatibility tests pass; no live import or repeat-import test was possible. |
| External provider intelligence ingestion | **NOT IMPLEMENTED** | No provider connectors or direct external-intelligence ingestion service were found. |
| Backend graph queries and API routes | **IMPLEMENTED BUT NOT FULLY TESTED** | Unit/route tests use mocked Neo4j; live query behavior is unverified. |
| Investigation attack-path integration | **IMPLEMENTED BUT NOT FULLY TESTED** | Existing query is exposed on demand and rendered in the investigation panel; no live graph IDs were tested. |
| Member 4 graph context / graph-aware risk | **PARTIALLY IMPLEMENTED** | Feature extraction exists, but live graph context is not wired into inference or priority scoring. |
| Constraints and indexes | **IMPLEMENTED BUT NOT FULLY TESTED** | Importer defines one uniqueness constraint; live presence and query plans are unverified. Additional indexes are not implemented. |
| Large-graph performance and concurrency | **NOT IMPLEMENTED** | No 100/1,000/10,000-node benchmarks or concurrency measurements were run. |
| Frontend production build | **BLOCKED BY ANOTHER MODULE** | `npm` is unavailable in the current environment; no build result is claimed. |
| Live Neo4j end-to-end testing | **BLOCKED BY ANOTHER MODULE** | Aura connectivity is unavailable; live database state was not inspected. |

## Test evidence and unverified items

The following local commands passed after the importer/validator changes:

| Command | Result |
|---|---|
| `python -m unittest discover -s backend\tests -v` | 43 tests passed |
| `$env:PYTHONPATH="member2_graph"; python -m unittest discover -s member2_graph\tests -v` | 19 tests passed |
| `python -m unittest discover -s tests -v` | 19 tests passed |
| `$env:PYTHONPATH="member2_graph"; python member2_graph\validate.py --fixture data\graph_fixture` | Offline fixture validation passed (18 entities, 17 events, 17 evidence, 68 relationships) |
| `git diff --check` | Passed |

These are local tests and synthetic-fixture validation only. No live ingestion,
live API-to-Neo4j investigation flow, Member 4 end-to-end graph analysis,
frontend build, performance benchmark, or external provider fetch was
performed. Actual performance results are therefore **not available**.
The backend test process also emitted a Neo4j driver `ResourceWarning` and a
Starlette/httpx deprecation warning; the tests still passed.

## Changed files in the current worktree

Modified:

- `backend/.env.example`
- `backend/app/config.py`
- `backend/app/database/queries.py`
- `backend/app/database/neo4j_connection.py`
- `backend/app/routes/investigations.py`
- `backend/app/services/investigation_service.py`
- `backend/tests/test_neo4j_connection.py`
- `backend/tests/test_investigation_routes.py`
- `docs/backend_api.md`
- `docs/ingestion_contract.md`
- `frontend/.env.example`
- `frontend/src/pages/Investigations.jsx`
- `frontend/src/services/api.js`
- `member2_graph/.env.example`
- `member2_graph/INTEGRATION.md`
- `member2_graph/README.md`
- `member2_graph/db.py`
- `member2_graph/importer.py`
- `member2_graph/validate.py`
- `src/trustrail_pipeline/graph_csv.py`
- `tests/test_pipeline.py`

New/untracked:

- `member2_graph/HANDOVER.md`
- `member2_graph/tests/test_importer_compatibility.py`
