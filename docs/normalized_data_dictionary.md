# Normalized data dictionary

The pipeline preserves a source value and separately reports normalized time. It does not synthesize missing timestamps, severity, labels, identities, or causal meaning.

| Field | Type | Notes |
|---|---|---|
| `event_id` | string | Stable within the same dataset ID and source record ID |
| `event_type` | string | `network_flow`, `authentication`, `process`, or `host_event` |
| `event_time` | string or null | UTC ISO string when defensible; otherwise original time string |
| `event_time_utc` | string or null | `Z`-suffixed UTC value, or null |
| `event_time_original` | string or null | Original source time value |
| `timestamp_semantics` | string | Explains conversion or unresolved source time |
| `ingestion_time` | string | UTC timestamp of the run start |
| `severity` | string or null | Copied only if supplied in the source |
| `source_system` | string | Supplied by run configuration |
| `source_record_id` | string | Source ID or input filename plus row/line locator |
| `source_entity_id` | string or null | Stable source endpoint/user/host reference |
| `target_entity_id` | string or null | Stable target endpoint/host/process reference |
| `relationship` | string or null | Evidence-backed candidate relation |
| `evidence_id` | string | Deterministic reference to provenance record |
| `evidence_status` | enum | `observed`, `synthetic`, `enriched`, or `derived` |
| `attributes` | object | Selected original fields, e.g. protocol, ports, logon status, process ID |

Entity and relationship property definitions are in [the ingestion contract](ingestion_contract.md). Source-specific semantics must be documented before adding mappings.
