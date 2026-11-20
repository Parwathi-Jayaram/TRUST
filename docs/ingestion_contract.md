# Member 3 JSONL export contract

This exporter follows Member 2's initial graph/import contract. The event-to-evidence and event-to-entity edge names below use the candidate types from the earlier Member 2 proposal and remain subject to Member 2's confirmation.

## Input

- One local CSV, JSON Lines, or small JSON file per run.
- Supported telemetry records include LANL-style network flows and host events.
- A graph-shaped record may provide `relationship_type`, `source_id`, `source_type`, `target_id`, and `target_type` to preserve an explicit relationship and its endpoint IDs.
- Explicit event, evidence, relationship, and endpoint IDs are preserved. Deterministic IDs are generated only when those IDs are absent from raw telemetry.
- Missing or invalid timestamps do not stop export: `event_time`/`observed_at` are `null`, the raw timestamp is retained, and `rejected.jsonl` records the validation issue.
- The source is never downloaded or modified.

## Output files

- `entities.jsonl`
- `relationships.jsonl`
- `events.jsonl`
- `evidence.jsonl`
- `rejected.jsonl`
- `metadata.json`

Each JSONL line is one record. `metadata.json` contains measured run counts and output names. `rejected.jsonl` contains the source locator, error, and raw timestamp when relevant; it does not copy the full source row.

## Record shapes

### Entity

Required: `id`, `type`, `synthetic`.

Optional: `name`, `criticality`. Explicit IDs are preserved exactly. Raw telemetry without entity IDs receives deterministic references.

### Security event

Required export properties: `event_id`, `event_type`, `event_time`, `severity`, `description`, `evidence_id`, `is_synthetic`.

Additional provenance/time fields include `event_time_original`, `timestamp_semantics`, `source_system`, `source_record_id`, `evidence_status`, and `ingested_at`. `event_time` is UTC ISO 8601 when timezone semantics are known; otherwise it is `null`, with the raw value retained in `event_time_original`.

### Evidence

Includes `evidence_id`, `event_id`, `source_system`, `source_record_id`, `observed_at`, `description`, `is_synthetic`, and provenance fields. Invalid or missing observation times are left `null`; any available raw value is kept separately.

### Relationship

Domain relationship records contain `relationship_id`, `source_id`, `target_id`, `relationship_type`, `evidence_status`, `event_id`, and `is_synthetic`. Explicit IDs and source-to-target direction are preserved. `relationship_id` is the import key so multiple assertions between the same endpoints remain distinct.

Supported explicit domain types are `AUTHENTICATED_TO`, `COMMUNICATES_WITH`, `RUNS`, `DEPENDS_ON`, `HAS_VULNERABILITY`, and `INVOLVES`.

| Relationship | Allowed source type | Allowed target type |
|---|---|---|
| `AUTHENTICATED_TO` | user | host |
| `COMMUNICATES_WITH` | host, server | ip, server |
| `RUNS` | host | process |
| `DEPENDS_ON` | server | application |
| `HAS_VULNERABILITY` | server | vulnerability |
| `INVOLVES` | incident | host, user |

The exporter also emits traceability edges:

| Source -> target | Relationship type |
|---|---|
| SecurityEvent -> Evidence | `SUPPORTED_BY` |
| SecurityEvent -> Entity | `OBSERVED_ON` |

These are provisional names pending Member 2 confirmation. Traceability relationships have deterministic IDs and the same required relationship properties.

## Status and synthetic data

`evidence_status` is kept separate from synthetic provenance and retains `observed`, `derived`, or `unconfirmed`. Synthetic origin is represented by the Boolean `synthetic`/`is_synthetic` fields, not by replacing the evidence status.

The bundled demo is illustrative synthetic data. It exercises the six domain relationship types and traceability edges but is not the separate 18-entity/17-relationship fixture Member 2 described. No real dataset has been downloaded or validated.

## Importer responsibilities

The exporter does not connect to Neo4j. The importer should validate required fields and endpoint types, use parameterized Cypher and `MERGE` keyed by the supplied IDs, batch transactions (initially 500 records), and roll back failed batches while retaining record-level errors. Missing optional properties may be null or omitted; the importer should not invent placeholders.
