# Member 3 JSONL export contract

This exporter follows Member 2's initial graph/import contract. The event-to-evidence and event-to-entity edge names below use the candidate types from the earlier Member 2 proposal and remain subject to Member 2's confirmation.

## Input

- One local CSV, JSON Lines, or small JSON file per run.
- Supported telemetry records include LANL-style network flows and host events.
- `ingest-graph` accepts a split graph dataset using `entities.csv`, `relationships.csv`, `events.csv`, and `evidence.csv`.
- A graph-shaped record may provide `relationship_type`, `source_id`, `source_type`, `target_id`, and `target_type` to preserve an explicit relationship and its endpoint IDs.
- Explicit entity, event, evidence, and original relationship IDs and source property values are preserved. Deterministic IDs are generated only for trace relationships or raw telemetry without IDs.
- Missing or invalid timestamps do not stop export: `event_time`/`observed_at` are `null`, the raw timestamp is retained, and `rejected.jsonl` records the validation issue.
- The source is never downloaded or modified.

## Output files

- `entities.jsonl`
- `relationships.jsonl`
- `events.jsonl`
- `evidence.jsonl`
- `rejected.jsonl`
- `metadata.json`

Each JSONL line is one record. `metadata.json` contains measured run counts and output names, including separate counts for original entity relationships and event trace relationships. `rejected.jsonl` contains the source locator, error, and raw timestamp when relevant; it does not copy the full source row.

## Record shapes

### Entity

Required: `id`, `type`, `synthetic`.

Optional: `name`, `criticality`. Values and IDs from `entities.csv` are preserved exactly, with the CSV Boolean converted to a JSON Boolean.

### Security event

Required export properties: `event_id`, `event_type`, `event_time`, `severity`, `description`, `evidence_id`, `is_synthetic`.

The split-CSV export also preserves `source_entity_id` and `target_entity_id`. Additional provenance/time fields include `event_time_original`, `timestamp_semantics`, `source_system` when available, `source_record_id`, and `ingested_at`. `event_time` is UTC ISO 8601 when timezone semantics are known; otherwise it is `null`, with the raw value retained in `event_time_original`.

### Evidence

Includes `evidence_id`, `event_id`, `source_system`, `source_record_id`, `observed_at`, `description`, `is_synthetic`, and provenance fields. Invalid or missing observation times are left `null`; any available raw value is kept separately.

### Relationship

Original entity relationship records contain `relationship_id`, `source_id`, `target_id`, `relationship_type`, `evidence_status`, `event_id`, `is_synthetic`, and `relationship_category: "original_entity"`. Explicit IDs and source-to-target direction are preserved. `relationship_id` is the import key so multiple assertions between the same endpoints remain distinct.

Supported explicit domain types are `AUTHENTICATED_TO`, `COMMUNICATES_WITH`, `RUNS`, `DEPENDS_ON`, `HAS_VULNERABILITY`, and `INVOLVES`.

| Relationship | Allowed source type | Allowed target type |
|---|---|---|
| `AUTHENTICATED_TO` | user | host |
| `COMMUNICATES_WITH` | host, server | ip, server |
| `RUNS` | host | process |
| `DEPENDS_ON` | server | application |
| `HAS_VULNERABILITY` | server | vulnerability |
| `INVOLVES` | incident | host, user |

Entity types are preserved from the source and compared case-insensitively by
the importer. `IPAddress` is accepted as an alias for `ip` in
`COMMUNICATES_WITH` endpoints.

The exporter also emits traceability edges with `relationship_category: "event_trace"`:

| Source -> target | Relationship type |
|---|---|
| SecurityEvent -> Evidence | `SUPPORTED_BY` |
| SecurityEvent -> Entity | `OBSERVED_ON` |

For `OBSERVED_ON`, `endpoint_role` identifies whether the entity came from the event's source or target endpoint. Traceability relationships have deterministic IDs and the same required relationship properties.

## Status and synthetic data

`evidence_status` is kept separate from synthetic provenance and retains `observed`, `derived`, or `unconfirmed`. Synthetic origin is represented by the Boolean `synthetic`/`is_synthetic` fields, not by replacing the evidence status.

The bundled demo is illustrative synthetic data. The separate `ingest-graph` command processes Member 2's authorized 18-entity/17-relationship fixture. This validates export and referential integrity against synthetic data only; no real dataset has been downloaded or validated.

## Importer responsibilities

The exporter does not connect to Neo4j. The importer should validate required fields and endpoint types, use parameterized Cypher and `MERGE` keyed by the supplied IDs, batch transactions (initially 500 records), and roll back failed batches while retaining record-level errors. Missing optional properties may be null or omitted; the importer should not invent placeholders.
