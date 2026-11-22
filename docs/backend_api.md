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
to the exact deployed frontend origin.

The backend may start while Neo4j is unavailable. Before relying on database-backed APIs,
confirm `GET /api/health` returns 200 using the deployment's database settings.
If it returns 503, the service may have a public URL, but database-backed
requests are not ready. Render and Neo4j must also be able to communicate over
the configured network.

Containment operations are simulation only.

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
| Investigations | `POST /api/investigations`, `GET /api/investigations`, `GET /{investigation_id}`, `POST /{investigation_id}/notes`, `POST /{investigation_id}/evidence`, `GET /{investigation_id}/evidence`, `PATCH /{investigation_id}/status`, `GET /{investigation_id}/timeline`, `POST /{investigation_id}/report-snapshots`, `GET /{investigation_id}/report-snapshots/{report_id}`, `GET /{investigation_id}/attack-paths?source_id=...&target_id=...&depth=3&limit=20` |

The investigation attack-path endpoint runs the existing bounded graph query
on demand; both endpoints must be linked to the investigation. It does not
persist results. Returned directed paths indicate possible graph connectivity,
not proof that an attacker traversed the path.

## Threat analysis integration

The backend is the only application orchestration/API layer. `create_app()`
creates one `Member4DetectionEngine` and exposes it through `app.state`.
`GET /api/threats` and `GET /api/threats/{threat_id}` use
`ThreatService.list_threats()` and `ThreatService.get_threat()`, respectively.
Those functions read `GraphNode:SecurityEvent` properties from Neo4j and call
`Member4DetectionEngine.predict_events()`. The evidence and associated-entity
endpoints call `get_threat()` first, so they also run inference before
retrieving linked graph records. `DashboardService.get_threat_distribution()`
uses the same detection-engine interface for a bounded event page.

`Member4DetectionEngine` loads the existing model and preprocessor from
`member4_ml/models`, calls Member 4's `predict_batch()` and
`compute_investigation_priority()`, and returns both model confidence and
investigation priority. It adapts the normalized event's optional `attributes`
object to the `attr_*` feature columns expected by the existing model. It does
not modify the stored event or introduce a second scoring formula. The
standalone API in `member4_ml/src/api.py` is not the backend's runtime path.

The analysis input is a `SecurityEvent` property map. `event_id` must be a
nonempty string; `attributes`, when present, must be an object of scalar
values. Common normalized properties include `event_type`, `event_time`,
`severity`, `description`, `evidence_id`, `evidence_status`, `is_synthetic`,
`source_entity_id`, `target_entity_id`, and optional `attributes`. Missing
feature values are handled by Member 4's existing preprocessor. Malformed
event identifiers or attributes return an explicit gateway error rather than
being silently dropped.

Threat results retain the event/evidence references (`event_id`,
`threat_id`, `evidence_id`, `entity_id`) and include the model
`prediction`, `attack_category`, `model_name`, `model_version`, `confidence`,
`model_confidence_percent`, `top_features`, and `explanation`. The separate
`risk_score`, `risk_level`, and `investigation_priority` fields are produced
by Member 4's deterministic scorer; the score is an investigation-priority
score, not model confidence or proof of compromise. `is_synthetic`,
`source_evidence_status`, and `limitations` preserve source provenance and
uncertainty. `evidence_status` is Member 4's `model_generated_signal` status;
it is not the source event's observed/derived/unconfirmed evidence status.
`GET /api/threats/evidence/{threat_id}` returns the linked Evidence records
when present.

Threat analysis response states:

| Condition | HTTP behavior |
|---|---|
| Event page has no records | `200`, empty `threats` list |
| Requested event is absent, or its prediction is not suspicious | `404` |
| Invalid pagination or other query parameters | `422` |
| Neo4j is unavailable | `503` |
| Member 4 model artifacts/dependencies are unavailable | `503` |
| Member 4 inference fails or Neo4j returns a malformed event | `502` |

Threat endpoints run only the existing local Member 4 model over Neo4j events.
No external threat-intelligence provider is implemented, so an empty threat
result is not an external reputation lookup or proof that an indicator is
safe. The committed graph fixture contains only synthetic data: it has
synthetic IP entity values and one simulated CVE-like entity, but no domains,
hashes, or populated network-flow `attributes`. No external provider is
recommended from those placeholder indicators, and no live Neo4j contents
were queried.

## Investigation report snapshots

`POST /api/investigations/{investigation_id}/report-snapshots` calls
`ReportDataService.create_snapshot()` and returns a validated
`InvestigationReportSnapshot`. The authenticated route captures persisted
investigation metadata, linked evidence, bounded graph subgraphs, and the
existing Member 4 assessment for a linked alert event. Member 4 failures leave
the graph/evidence in place and produce an unavailable risk status with a
null score.
The Investigation Workspace exposes capture and reload actions and displays
the snapshot summary, risk status, graph/evidence counts, event provenance,
and limitations.

The snapshot contains `source_evidence_status` from the stored event,
`model_generated_signal` as model provenance, and Member 4's `prediction` as
separate fields. The risk score, when present, is Member 4's existing
investigation-priority score; it is not confidence or a probability of
compromise. External threat intelligence and AI explanations are marked
`not_implemented`, so current snapshots are explicitly partial.

Snapshots are stored as serialized payloads on `ReportSnapshot` nodes that
are not labeled `GraphNode`; they do not become graph evidence. The API has no
update/delete operation. `GET
/api/investigations/{investigation_id}/report-snapshots/{report_id}` returns
the captured payload without re-running analysis. Graph collection is bounded
to 20 entities, depth 2, and 10 paths per entity; evidence to 100 records;
descriptive strings to 4,000 characters; and the serialized payload to 1 MB.
Omitted or truncated data is recorded in limitations and sets `partial`.
Malformed stored payloads return 502, missing snapshots 404, Neo4j failures
503, and over-limit snapshots 413.
In synthetic development mode, the adapter stores snapshots in memory only.
The source service reads are separate Neo4j transactions, so the persisted
payload is stable after capture but is not guaranteed to represent one
transactionally consistent point-in-time database view. No snapshot retention
or deletion policy is configured.

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
- External threat-intelligence APIs (including AbuseIPDB, OTX, NVD, CISA KEV,
  OSV, and Wazuh) are not implemented or queried.
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
