# Member 2 — Neo4j Graph Database & Ingestion

TRUSTRAIL AI Member 2 owns the Neo4j graph database and the JSONL importer that
loads Member 3's graph-ready exports into it. It also provides read-only graph
service helpers. The FastAPI backend exposes the HTTP endpoints; this module
does not connect the frontend directly to Neo4j or perform real containment.

## Repository layout

```
member2_graph/
  db.py             # Neo4j driver connection module (singleton, error handling)
  importer.py       # JSONL importer: entities, events, evidence, relationships
  validate.py       # Standalone fixture validation + Neo4j validation queries
  README.md         # this file
  .env.example      # credential template (no passwords) — copy to .env
  .env              # local credentials — GITIGNORED, never commit
  requirements.txt  # neo4j, python-dotenv

data/graph_fixture/  # synthetic Member 3 export used for import testing
```

## Prerequisites

- Python 3.10+
- A Neo4j Aura instance (URI, username, password)

Install dependencies:

```powershell
$env:PYTHONPATH = "member2_graph"
pip install -r member2_graph/requirements.txt
```

## Environment configuration

1. Copy `member2_graph/.env.example` to `member2_graph/.env`.
2. Fill in your Neo4j Aura credentials:

```
NEO4J_URI=neo4j+s://<your-instance>.databases.neo4j.io
NEO4J_USERNAME=<your-neo4j-username>
NEO4J_PASSWORD=<your-aura-password>
NEO4J_DATABASE=<your-database-name>
```

3. **Never commit `.env`.** It is excluded from Git via the root `.gitignore`
   (`.env` pattern matches any directory). `.env.example` contains no
   passwords and is safe to commit.

Credentials are read from the environment (`.env` loaded by
`python-dotenv`, without overwriting existing variables) and are never
logged or written to reports.

The Member 2 importer reads `member2_graph/.env`. The FastAPI backend reads
the repository-root `.env` during local development, so keep the Neo4j
settings consistent in both files. On Render, set the variables in the
service's environment settings instead of uploading either `.env` file.

## Connection module (`db.py`)

`get_driver()` returns a lazily-initialized, singleton Neo4j driver.
`verify_connectivity()` checks reachability and reports failures without
exposing credentials. `session()` is a context manager that guarantees
session cleanup.

The FastAPI backend sets a connection timeout of 10 seconds and a transaction
timeout of 30 seconds by default. `NEO4J_QUERY_TIMEOUT_SECONDS` can be set
between 1 and 120 seconds for backend read/write transactions.

Self-check (shows configured URI only; reports connection failure cleanly
when Aura is unreachable):

```powershell
$env:PYTHONPATH = "member2_graph"
python member2_graph/db.py
```

## Database schema

The importer creates a uniqueness constraint on the shared node ID:

```cypher
CREATE CONSTRAINT graph_node_id IF NOT EXISTS
FOR (n:GraphNode) REQUIRE n.id IS UNIQUE;
```

Node labels are `GraphNode:Entity`, `GraphNode:SecurityEvent`, and
`GraphNode:Evidence`. Every node has a shared `id`; events and evidence also
retain `event_id` and `evidence_id` respectively for API lookups.

Relationships (all directed, source → target), keyed by `relationship_id`:
- Domain (`relationship_category = 'original_entity'`): `AUTHENTICATED_TO`,
  `COMMUNICATES_WITH`, `RUNS`, `DEPENDS_ON`, `HAS_VULNERABILITY`, `INVOLVES`
  between `(:GraphNode:Entity)-[]->(:GraphNode:Entity)`, endpoint types validated against
  `docs/ingestion_contract.md`.
- Trace (`relationship_category = 'event_trace'`):
  - `(:GraphNode:SecurityEvent)-[:SUPPORTED_BY]->(:GraphNode:Evidence)`
  - `(:GraphNode:SecurityEvent)-[:OBSERVED_ON]->(:GraphNode:Entity)` with `endpoint_role` (`source`/`target`).

Original IDs, relationship directions, `evidence_status`, and `is_synthetic`
flags are preserved. Optional properties absent from a record are not invented.
Entity types are checked case-insensitively; `IPAddress` is accepted as an
alias for `ip` on `COMMUNICATES_WITH` edges.

## Backend API integration

The FastAPI backend owns the user-facing HTTP API and queries Neo4j using the
same labels and IDs described above. The frontend calls FastAPI; it must not
connect to Neo4j directly. The separate `src/graph_service.py` class is a
Python library helper and is not mounted as a second set of FastAPI routes.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/graph/overview` | Graph node and relationship counts |
| `GET` | `/api/graph/entities` | Filtered, paginated entity list |
| `GET` | `/api/graph/entity/{entity_id}` | Retrieve an entity |
| `GET` | `/api/graph/neighbors/{entity_id}` | Retrieve neighboring nodes and edges |
| `GET` | `/api/graph/relationships/{entity_id}` | Retrieve relationships for an entity |
| `GET` | `/api/graph/subgraph/{entity_id}?depth=2&limit=100` | Retrieve a bounded subgraph |
| `GET` | `/api/graph/attack-paths/{source_id}/{target_id}?depth=3&limit=20` | Explore directed paths |
| `GET` | `/api/investigations/{investigation_id}/attack-paths?source_id=...&target_id=...&depth=3&limit=20` | Explore directed paths between entities linked to an investigation |
| `GET` | `/api/blast-radius/{entity_id}?depth=2` | Analyze potentially reachable entities |
| `POST` | `/api/blast-radius/analyze` | Analyze blast radius from a JSON request |
| `POST` | `/api/containment/simulate` | Compare a hypothetical graph; does not change Neo4j |
| `POST` | `/api/containment/compare` | Compare multiple hypothetical scenarios |
| `GET` | `/api/containment/recommendations/{incident_id}` | Get simulation recommendations |

`/api/graph/entities` accepts `entity_type`, `risk_level`, `skip`, and `limit`.
Subgraph, attack-path, and blast-radius requests accept a bounded `depth`.
The investigation attack-path endpoint requires distinct source and target
IDs linked to that investigation; it runs the same graph query on demand and
does not save the results. Directed paths represent possible graph
connectivity, not proof of attacker traversal. Single-entity lookups return
`404` for missing IDs, attack-path requests may return an empty path list, and
depths over the configured maximum return `422`.

Successful backend responses use a JSON envelope with `success` and `data`.
Depth is bounded by `MAX_GRAPH_DEPTH` (default 4, maximum 6). In production,
API routes require a bearer token; `/api/health` and `/healthz` are public.

Threat inference is integrated with Member 4, but Member 4's graph feature
extractor is not currently wired into backend inference. The investigation
priority score therefore does not include graph context yet.

## Import commands

Generate/refresh the synthetic fixture (Member 3 export) — already present:

```powershell
# data/graph_fixture/ contains entities.jsonl, events.jsonl, evidence.jsonl,
# relationships.jsonl, rejected.jsonl, metadata.json
```

For a different split-CSV dataset, export it first:

```powershell
$env:PYTHONPATH = "src"
python -m trustrail_pipeline.cli ingest-graph --entities path\to\entities.csv --relationships path\to\relationships.csv --events path\to\events.csv --evidence path\to\evidence.csv --output-dir data\graph_fixture
```

The CSV columns and relationship direction must follow
`docs/ingestion_contract.md`. Validate the JSONL export before importing.

Run the importer:

```powershell
$env:PYTHONPATH = "member2_graph"
python member2_graph/importer.py --input-dir data/graph_fixture --batch-size 500
```

Sample output:

```
============================================================
Member 2 — JSONL import report
============================================================
Entities:      18 imported / 18 read
Events:        17 imported / 17 read
Evidence:      17 imported / 17 read
Relationships: 68 imported / 68 read
Errors:        0
Failed batches:0
============================================================
```

## Database reset

To wipe the graph before a re-import (Neo4j Browser or `cypher-shell`):

```cypher
MATCH (n) DETACH DELETE n;
```

**Warning:** this deletes every node and relationship in the selected database.
Use it only for a dedicated disposable demo database, after confirming the
database selection and making any required backup.

The importer uses `MERGE` keyed on supplied IDs, so importing the same fixture
again is designed not to create duplicate nodes or relationships. It updates
supplied non-null properties for matching IDs and reports validation or batch
errors. The live repeated-import check has not been run in this environment.

## Validation

Standalone fixture validation (no Neo4j required — checks record structure,
counts, relationship directions, and endpoint validity):

```powershell
$env:PYTHONPATH = "member2_graph"
python member2_graph/validate.py --fixture data/graph_fixture
python -m unittest discover -s member2_graph/tests -v
python -m unittest discover -s tests -v
```

For the FastAPI route and backend-to-graph integration tests, install
`backend/requirements.txt` and run:

```powershell
python -m pip install -r backend/requirements.txt
python -m unittest discover -s backend/tests -v
```

Expected synthetic totals (validated above):

| Item | Count |
|---|---|
| Entities | 18 |
| Events | 17 |
| Evidence records | 17 |
| Domain relationships (`original_entity`) | 17 |
| Trace `SUPPORTED_BY` | 17 |
| Trace `OBSERVED_ON` | 34 |
| Total relationships | 68 |
| Rejected records | 0 |

Neo4j validation queries (run against a live connection via
`validate.py.run_neo4j_validation(driver)` or Neo4j Browser):

```cypher
-- Node counts
MATCH (n:GraphNode:Entity) RETURN count(n) AS entities;              -- expect 18
MATCH (n:GraphNode:SecurityEvent) RETURN count(n) AS events;          -- expect 17
MATCH (n:GraphNode:Evidence) RETURN count(n) AS evidence;             -- expect 17

-- Relationship counts
MATCH ()-[r]-() RETURN count(r) AS total;              -- expect 68
MATCH ()-[r]-() WHERE r.relationship_category = 'original_entity' RETURN count(r);  -- 17
MATCH ()-[r]-() WHERE r.relationship_category = 'event_trace' RETURN count(r);      -- 51
MATCH ()-[r:SUPPORTED_BY]->() RETURN count(r);         -- 17
MATCH ()-[r:OBSERVED_ON]->() RETURN count(r);          -- 34

-- Directions
MATCH (e:GraphNode:SecurityEvent)-[r:SUPPORTED_BY]->(v:GraphNode:Evidence) RETURN count(r); -- 17
MATCH (e:GraphNode:SecurityEvent)-[r:OBSERVED_ON]->(t:GraphNode:Entity) RETURN count(r);    -- 34

-- Idempotency: re-run the importer, counts must be unchanged
```

## Idempotency / duplicate prevention

Every node is `MERGE`d on the shared `GraphNode.id`. Every relationship is `MERGE`d on
`relationship_id` between its endpoints. Importing the same fixture twice
produces identical counts with no duplicate nodes or relationships. Invalid
records are reported, and failed batches are rolled back.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Missing Neo4j credentials` | `.env` absent or incomplete | Copy `.env.example` to `.env` and fill URI/username/password |
| `Cannot resolve address ...` | Wrong `NEO4J_URI` | Use your Aura instance hostname, port 7687 (`neo4j+s://`) |
| `AuthError` / `Neo4jError` | Bad username/password | Verify `NEO4J_USERNAME`/`NEO4J_PASSWORD` in `.env` |
| Relationship import fails | Endpoint type mismatch | Check source/target types and relationship direction in the fixture |
| Backend returns empty graph results | Importer/schema mismatch | Confirm nodes use `GraphNode` plus the type label; re-import only after backing up any existing data |

## Notes

- No real Neo4j Aura endpoint was reachable in this environment, so the
  end-to-end import against Aura could not be executed here. The connection
  module, importer, and fixture validation are implemented and tested; when
  credentials are configured, run the import command above and the Neo4j
  validation queries to confirm the expected totals.
- The standalone fixture and importer compatibility tests run without Aura.
  The live import, live API workflow, and Render deployment still require a
  reachable Neo4j database and hosting-provider environment variables.
- `.env` is never committed and contains no credentials in `.env.example`.

## Audit and handover

See [HANDOVER.md](HANDOVER.md) for the audited architecture, schema and
integration status, test evidence, unverified items, and handoff instructions
for Members 3, 4, and 5.
