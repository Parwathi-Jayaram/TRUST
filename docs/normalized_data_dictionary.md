# Member 3 normalized data dictionary

The pipeline emits `entities.jsonl`, `relationships.jsonl`, `events.jsonl`, `evidence.jsonl`, `rejected.jsonl`, and `metadata.json`. See [the JSONL contract](ingestion_contract.md) for record requirements and edge directions.

## Entities

| Field | Type | Notes |
|---|---|---|
| `id` | string | Explicit input ID preserved; otherwise deterministic source reference |
| `type` | string | Entity type used by the importer to select Neo4j labels |
| `synthetic` | boolean | Whether the entity is synthetic |
| `name` | value, optional | Source value when available |
| `criticality` | value, optional | Included only when supplied |

## Security events

| Field | Type | Notes |
|---|---|---|
| `event_id` | string | Explicit input ID preserved; otherwise deterministic |
| `event_type` | string | Normalized event category or explicit input type |
| `event_time` | string or null | UTC ISO 8601 only when source time semantics are known |
| `event_time_original` | string or null | Raw source timestamp, including invalid values |
| `timestamp_semantics` | string | `iso8601`, `unix_seconds`, `timezone_missing`, `source_numeric_time_unresolved`, `unparseable`, or `missing` |
| `severity` | value or null | Copied only if supplied |
| `description` | value or null | Copied only if supplied |
| `evidence_id` | string | Explicit or deterministic provenance reference |
| `is_synthetic` | boolean | Synthetic provenance flag |
| `source_system` | string | Supplied by run configuration |
| `source_record_id` | string | Source ID or input filename plus row/line locator |
| `ingested_at` | string | UTC time at the start of the pipeline run |
| `evidence_status` | enum | `observed`, `derived`, or `unconfirmed` |

## Evidence and relationships

Evidence records retain event/source IDs, `observed_at` and its raw value, `ingested_at`, description, source provenance, evidence status, and synthetic flag.

Relationship records use `relationship_id` as their stable import key and retain `source_id`, `target_id`, `relationship_type`, `event_id`, `evidence_status`, and `is_synthetic`. Explicit source-to-target direction is preserved. Event-to-evidence and event-to-entity trace edges are emitted as `SUPPORTED_BY` and `OBSERVED_ON`, respectively; confirm those names with Member 2 before treating them as final.

Invalid timestamps produce an event with `event_time: null`, preserve the raw value, and add a recoverable validation entry to `rejected.jsonl`. No timestamp is fabricated.
