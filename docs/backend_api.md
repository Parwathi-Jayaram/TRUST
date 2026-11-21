# TRUSTRAIL AI Phase 1 Backend

The backend is a modular FastAPI application. It connects the React client to
the existing Neo4j `GraphNode` schema, reads Member 3 graph data, and invokes
Member 4's bundled prediction and investigation-priority interfaces.

## Run locally

From the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
Copy-Item backend\.env.example .env
# Edit .env with Neo4j credentials and the frontend origin.
python -m uvicorn backend.app.main:app --reload
```

Interactive API documentation: `http://127.0.0.1:8000/docs`.

The Neo4j health endpoint is `GET /api/health`. It returns HTTP 503 when Neo4j
is missing or unavailable; the application can still start so API and UI
development do not require a live database. Credentials are read from the
environment and must never be placed in frontend code.

## Render deployment

The root `render.yaml` defines a Python web service. In Render, create a
Blueprint from the GitHub repository and select the branch containing this
file. Configure the prompted `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`,
`NEO4J_DATABASE`, `API_BEARER_TOKEN`, and `CORS_ORIGINS` values in Render's
environment settings. Do not commit these values or put the bearer token in a
`VITE_` frontend variable.

Production requires `API_BEARER_TOKEN`; the service refuses to start without
it. The frontend asks each user to enter that token and keeps it in
`sessionStorage`. Share the token through an approved private channel. The
`GET /healthz` liveness check is public for Render and returns only process
status. `GET /api/health` separately checks Neo4j and may return 503 while the
database is unavailable. API docs are disabled in production. CORS must be set
to the deployed frontend's exact origin. Generate the token locally with
`python -c "import secrets; print(secrets.token_urlsafe(32))"` and enter it
directly in Render's environment settings.

For the separately hosted frontend, set these build-time variables:

```text
VITE_API_BASE_URL=https://<render-service>.onrender.com/api
VITE_API_AUTH_REQUIRED=true
```

Render probes `/healthz`, which checks process liveness only; that check can
succeed while Neo4j is unavailable. Before relying on database-backed APIs,
confirm `GET /api/health` returns 200 using the deployment's database settings.
If it returns 503, the service may have a public URL, but database-backed
requests are not ready. Render and Neo4j must also be able to communicate over
the configured network.

## API groups

Successful responses use `{ "success": true, "message": "...", "data": ... }`.
Database and detection failures return explicit non-2xx responses. In
production, all API routes except `GET /api/health` require the configured
bearer token.

| Group | Endpoints |
|---|---|
| Health | `GET /api/health` |
| Dashboard | `GET /api/dashboard/overview`, `/threat-distribution`, `/recent-activity` |
| Graph | `GET /api/graph/overview`, `/entities`, `/entity/{entity_id}`, `/neighbors/{entity_id}`, `/relationships/{entity_id}`, `/subgraph/{entity_id}` |
| Threats | `GET /api/threats`, `/high-risk`, `/{threat_id}`, `/associated-entities/{threat_id}`, `/evidence/{threat_id}` |
| Incidents | `GET /api/incidents`, `GET /{incident_id}`, `POST /api/incidents`, `PATCH /{incident_id}/status`, `PATCH /{incident_id}/priority`, `GET /{incident_id}/timeline` |
| Blast radius | `GET /api/blast-radius/{entity_id}`, `POST /api/blast-radius/analyze` |
| Containment | `POST /api/containment/simulate`, `/compare`, `GET /api/containment/recommendations/{incident_id}` |
| Investigations | `POST /api/investigations`, `GET /api/investigations`, `GET /{investigation_id}`, `POST /{investigation_id}/notes`, `POST /{investigation_id}/evidence`, `GET /{investigation_id}/evidence`, `PATCH /{investigation_id}/status`, `GET /{investigation_id}/timeline`, `GET /{investigation_id}/attack-paths?source_id=...&target_id=...&depth=3&limit=20` |

The investigation attack-path endpoint runs the existing bounded graph query
on demand; both endpoints must be linked to the investigation. It does not
persist results. Returned directed paths indicate possible graph connectivity,
not proof that an attacker traversed the path.

Graph list endpoints are paginated. Graph traversal depth is bounded by
`MAX_GRAPH_DEPTH` (default 4, maximum 6); subgraph and blast-radius queries also
cap returned paths. The implementation uses the existing `GraphNode`, `Entity`,
`SecurityEvent`, `Evidence`, `OBSERVED_ON`, `SUPPORTED_BY`, and original
relationship conventions.

## Data and safety limitations

- Dashboard entity counts come from Neo4j. Metrics without a confirmed source
  property are returned as unavailable, not fabricated as zero.
- Threat endpoints run Member 4 inference on bounded pages of normalized
  events. The bundled model is based on a small synthetic dataset; its output
  is an analyst signal, not proof of compromise.
- `model_confidence` and the Member 4 investigation-priority `risk_score` are
  distinct. Graph context is not yet incorporated into that priority score.
- The current entity contract has no confirmed compromise or `risk_level`
  property. Blast-radius results are therefore labeled potential exposure;
  risk-level filtering reports unavailable when no such properties exist.
- Incident and investigation status/audit entries are stored on their
  `GraphNode:Entity` records. Audit actors are recorded as `backend_api`
  because user authentication is not part of this phase.
- Containment endpoints are strictly simulation-only. They compare graph
  reachability before and after excluding selected entities; they do not
  isolate hosts, disable accounts, block IPs, alter firewalls, or write
  containment changes to Neo4j.
- Some integration tests use mocked Neo4j responses. Cypher execution and
  importer compatibility must still be verified against a configured Neo4j
  instance before a live demonstration.

## Validate

```powershell
python -m unittest discover -s backend\tests -v
python -m unittest discover -s tests -v
```

Neo4j credentials are not required for these unit tests.
