# Provisional ingestion and graph-export contract

This contract is a Member 3 proposal aligned to the candidate fields in Member 2's brief. Member 2's brief says its schema is a starting proposal, not mandatory final schema. Confirm this contract using representative source records before using the exports in a graph.

## Input

- One local CSV, JSON Lines, or JSON file per run.
- Each record must be an object/row with a source time and one recognized shape:
  - Network flow: `Time`, `SrcDevice`, `DstDevice`.
  - Host event: `EventID`, `Time`, plus a host and/or recognized user/process field.
- For a reproducible event ID, provide `RecordID`, `record_id`, `event_id`, `id`, or `_id`. If absent, the pipeline uses `<input-filename>#<record-locator>`.
- The operator supplies dataset ID, source system, version, URL/license where known, and evidence status.
- No remote download, API request, scan, or source-file modification occurs.

## Normalized event

Required output properties:

| Property | Meaning |
|---|---|
| `event_id` | Deterministic ID derived from dataset ID and source record ID |
| `event_type` | `network_flow`, `authentication`, `process`, or `host_event` |
| `event_time` | UTC ISO 8601 when timezone/epoch semantics are known; otherwise the original time string |
| `event_time_utc` | Normalized UTC timestamp or `null` |
| `event_time_original` | Original source value as text |
| `timestamp_semantics` | `iso8601`, `unix_seconds`, `timezone_missing`, `source_numeric_time_unresolved`, `unparseable`, or `missing` |
| `ingestion_time` | UTC time when this pipeline run began |
| `source_system` | Operator-supplied source name |
| `source_record_id` | Source record ID or stable file/locator fallback |
| `source_entity_id`, `target_entity_id` | Stable references when applicable |
| `relationship` | Candidate Member 2 type or `null` if no supported relationship is justified |
| `evidence_id` | Deterministic evidence reference |
| `evidence_status` | `observed`, `synthetic`, `enriched`, or `derived` |
| `attributes` | Selected source fields preserved without inferring labels |

## Candidate graph records

Entities use Member 2's proposed common fields (`id`, `name`, `entity_type`, `source`, `environment`, `status`) plus source system. Entity IDs are namespaced SHA-256 references derived from dataset, entity type, and normalized source value; names remain source values and should only be used with public/de-identified or explicitly authorized input. Process IDs include the host, source process ID when available, and source record ID so process instances are not collapsed by executable name alone. Event/evidence records carry observation times; entity records do not collapse changing observations into one timestamp.

Relationships contain `id`, `source_entity_id`, `target_entity_id`, `relationship`, `event_time`, `source_system`, `evidence_id`, `evidence_status`, and a properties object referencing the event. The current supported candidates are:

| Source -> target | Relationship | Evidence rule |
|---|---|---|
| User -> Host | `AUTHENTICATED_TO` | Explicit successful authentication event only |
| Host/IPAddress -> Host/IPAddress | `COMMUNICATES_WITH` | Explicit network-flow row; source direction is preserved |
| Host -> Process | `RUNS` | Explicit process-start event (LANL EventID 4688) |

Authentication failures and logoff records remain events but do not produce `AUTHENTICATED_TO`. Unknown timestamp semantics are retained and are not silently converted to UTC.

Evidence records include `evidence_id`, `source_record_id`, `source_system`, `source_dataset_id`, source version/URL/license, observed/ingested times, evidence type, and status. Rejected records include the locator and reason but not the raw row.

## Output files

The run writes `events.jsonl`, `entities.jsonl`, `relationships.jsonl`, `evidence.jsonl`, `rejected.jsonl`, and a measured `report.json`. Outputs replace prior files only after successful processing. Member 2 must confirm final labels, required fields, relationship direction, time semantics, null policy, and idempotency before graph ingestion.
