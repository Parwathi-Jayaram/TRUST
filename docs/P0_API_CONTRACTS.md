# TRUSTRAIL AI P0 API Contracts

**Status:** Existing backend contracts plus the implemented report-snapshot
interface and investigation-page integration. The PDF renderer is unchanged.

## Common response and errors

Most successful application API routes return:

```json
{
  "success": true,
  "message": "Success",
  "data": {}
}
```

`GET /api/health` is currently an unwrapped status response. `GET /healthz`
is a public liveness response. Production API routes use the shared bearer
token middleware; the health endpoints and CORS preflight are exempt.

Current error behavior includes:

| Status | Meaning |
|---|---|
| `401` | Missing or invalid configured bearer token. |
| `404` | Investigation, graph entity, event, or referenced record not found. |
| `409` | Invalid state transition or concurrent state update. |
| `422` | Request validation, query bounds, or linked-path validation failed. |
| `502` | Member 4 inference failure or malformed stored threat event. |
| `503` | Neo4j or Member 4 model unavailable. |
| `413` | Serialized report snapshot exceeds the 1 MB limit, or an identifier exceeds the supported bound. |

The exception handlers return `{success:false,message,data:null}` for handled
service exceptions. Report snapshot errors map missing records to `404`,
oversized payloads to `413`, malformed stored data to `502`, and Neo4j failures
to `503`.

## Existing investigation API

| Method and route | Input | Current result |
|---|---|---|
| `POST /api/investigations` | `title`, optional `alert_id`, `entity_ids` (up to 50) | `201`; creates an `OPEN` graph-backed investigation. |
| `GET /api/investigations` | Optional `status`, `alert_id`, `skip`, `limit` (1–200) | Paginated investigation list. |
| `GET /api/investigations/{investigation_id}` | Path ID | Investigation details, notes, and audit history. |
| `POST /api/investigations/{id}/notes` | `content` (1–10,000 chars) | Adds note and audit entry. |
| `POST /api/investigations/{id}/evidence` | `evidence_id` | Attaches existing evidence; duplicate attachment is idempotent. |
| `GET /api/investigations/{id}/evidence` | Path ID | Attached evidence records. |
| `PATCH /api/investigations/{id}/status` | `status` (`OPEN`, `IN_PROGRESS`, `CLOSED`) and optional note | Validated status transition and audit entry. |
| `GET /api/investigations/{id}/timeline` | Path ID | Existing audit history. |
| `POST /api/investigations/{id}/report-snapshots` | Path ID | `201`; captures and persists a new immutable report snapshot. |
| `GET /api/investigations/{id}/report-snapshots/{report_id}` | Path IDs | Retrieves the captured snapshot without re-running analysis. |
| `GET /api/investigations/{id}/attack-paths` | `source_id`, `target_id`, bounded `depth`/`limit` | On-demand path result; both distinct endpoints must be linked to the investigation. |

Current creation only persists workflow metadata. It does not orchestrate all
graph, threat, risk, and AI services.

## Existing service interfaces

Current callable service methods include:

```text
InvestigationService.create_investigation(
    title: str,
    alert_id: str | None,
    entity_ids: list[str],
) -> dict

InvestigationService.get_investigation(investigation_id: str) -> dict
InvestigationService.list_investigations(
    status: str | None,
    alert_id: str | None,
    skip: int,
    limit: int,
) -> dict

GraphService.get_entity(entity_id: str) -> dict | None
GraphService.get_subgraph(entity_id: str, depth: int, limit: int) -> dict | None
GraphService.find_attack_paths(
    source_id: str, target_id: str, depth: int = 3, limit: int = 20
) -> dict

Member4DetectionEngine.predict_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]

ThreatService.analyze_event(
    event_id: str,
) -> dict[str, Any] | None

ReportDataService.create_snapshot(
    investigation_id: str,
) -> InvestigationReportSnapshot

ReportDataService.get_snapshot(
    investigation_id: str,
    report_id: str,
) -> InvestigationReportSnapshot
```

`Member4DetectionEngine` adapts normalized event attributes to the existing
`attr_*` model feature columns and calls Member 4's predictor and
`compute_investigation_priority`. The backend currently does not supply graph
context to the scorer. Do not pass raw Neo4j driver objects into Member 4.

Member 3 currently provides local normalization/export, not an external
intelligence service function. No threat provider's availability, error, or
finding schema can therefore be claimed.

## Report snapshot contract

Member B's agreed top-level shape is:

```text
InvestigationReportSnapshot
├── investigation
├── executive_summary
├── findings[]
├── risk_assessment
├── threat_intelligence
├── graph
├── ai_explanation
├── evidence[]
├── provenance
├── limitations[]
├── partial
├── report_id
├── snapshot_captured_at
└── schema_version
```

### Nested section types and statuses

- `investigation`: `id`, `title`, `status`, optional `alert_id`, linked
  `entity_ids` and `evidence_ids`, timestamps, and `is_synthetic`.
- `executive_summary`: `status`, deterministic factual `text`, and
  `evidence_ids`. This is not an LLM explanation.
- `findings[]`: event and model references, including `event_id`,
  `source_evidence_status`, and the separate `model_generated_signal`, plus
  the model `prediction`, model/version, confidence, Member 4 priority
  score/level, evidence IDs, and limitations.
- `risk_assessment`: status, nullable score/level, score kind/model version,
  evidence IDs, and warnings. Any score is Member 4's existing
  investigation-priority output, not a new scoring formula or probability.
- `threat_intelligence`: status, provider names, findings, and warnings. It is
  `not_implemented`; no external API is queried.
- `graph`: status, bounded per-entity subgraphs, warnings, and an
  interpretation that graph paths are not proof of attacker movement.
- `ai_explanation`: status, nullable summary, evidence IDs, and limitations.
  It is `not_implemented`.
- `evidence[]`: actual persisted evidence property maps.
- `provenance`: source service names and an `is_synthetic` flag.
- `limitations[]`, `partial`, `report_id` (`RPT-` plus UUID hex),
  `snapshot_captured_at` (UTC ISO-8601), and `schema_version` (`1.0`).

Section status values are `completed`, `partial`, `unavailable`,
`not_implemented`, `not_applicable`, and `insufficient_evidence`.

- Populate values only from actual persisted investigation data or verified
  existing services. Do not invent a summary, finding, score, provider result,
  AI explanation, source URL, or graph relationship.
- Keep synthetic provenance explicit and distinct from evidence status.
- Preserve `evidence_id`, source references, and source timestamps when
  present.
- Represent unimplemented external intelligence and AI as unavailable or
  not implemented, not as empty/negative findings.
- Label graph reachability as potential exposure, not proof of compromise.
- `partial` is true when a requested section is unavailable/incomplete.
  Because external intelligence and AI explanation are not implemented,
  current report snapshots are explicitly partial.
- A report snapshot must not silently change after capture. The storage and
  retrieval design must preserve the captured payload and `report_id`.
- Bound graph, text, evidence, and serialized response sizes. Record truncation
  or omitted sections as limitations rather than silently dropping data.

### Callable interface and routes

`POST /api/investigations/{investigation_id}/report-snapshots` calls
`create_snapshot`; `GET
/api/investigations/{investigation_id}/report-snapshots/{report_id}` calls
`get_snapshot`. Both use the existing shared bearer-token middleware and
standard `{success, message, data}` response envelope.

Creation reads the stored investigation and linked evidence, uses the current
`GraphService` for up to 20 linked-entity subgraphs (depth at most 2, at most
10 paths per entity), and uses `ThreatService.analyze_event()` for a linked
event. Member 4 unavailability or inference failure yields a partial snapshot
with a null score rather than a fabricated default. Evidence is bounded to
100 records; descriptive strings are bounded to 4,000 characters; serialized
payloads are limited to 1 MB.

Neo4j stores each payload as JSON on a `ReportSnapshot` node, separate from
`GraphNode`, so snapshots do not become graph evidence or affect graph
traversals. The API has no update/delete operation. Retrieval returns the
stored JSON and does not re-run graph or model analysis. In synthetic
development mode snapshots are in-memory only. Source reads use separate
Neo4j transactions, so the persisted payload is stable after capture but is
not guaranteed to represent one transactionally consistent point-in-time
database view; no retention/deletion policy is configured.

### Snapshot errors

| Condition | HTTP behavior |
|---|---|
| Investigation missing during creation | `404` |
| Snapshot ID/investigation pair not found | `404` |
| Neo4j unavailable | `503` |
| Malformed stored snapshot payload | `502` |
| Snapshot exceeds size bounds | `413` |
| Member 4 unavailable/fails during creation | `201` partial snapshot with unavailable risk status and warning |
| No alert event linked or event absent | `201` partial snapshot with insufficient-evidence risk status and null score |

## Existing dependency behavior

- `/api/health` currently reports Neo4j health only. `/api/ready` is not
  implemented.
- Neo4j connection/query errors map to `503`.
- Member 4 missing artifacts/dependencies map to `503`; inference errors map
  to `502`.
- Report snapshot creation handles those Member 4 failures as partial `201`
  results with no invented score; graph and evidence remain included.
- No threat-intelligence provider error/status mapping exists.
- No Ollama/LLM status or timeout mapping exists.
- No report snapshot error mapping exists.

## Bounds and security

- Graph list and traversal routes apply pagination, depth, and result limits.
- Investigation creation limits linked entity count; notes and request fields
  have Pydantic length limits.
- Cypher is defined by the backend and values are parameterized.
- A shared bearer token does not provide analyst identity or per-investigation
  authorization. Do not claim individual ownership or role permissions.
- There is no general request-size limit or rate limiter.
- Do not log request credentials or full event/evidence payloads.
