# Data-quality report format

Each pipeline run creates `metadata.json` from observed execution results. No example counts in documentation are presented as actual source measurements.

For the single-file telemetry mode, the report records:

- source dataset/system/version, file, format, size, license/URL if supplied, and evidence status;
- transform version, start/end time, and measured duration;
- `records_read`, `records_accepted`, `records_rejected`, `invalid_records`, `duplicates_skipped`, `timestamps_unresolved`, `entities`, `relationships_seen`, `relationships`, `domain_relationships`, `traceability_relationships`, and `evidence_records` counts.

For split graph CSV input, `metadata.json` records per-file sizes and the measured counts for `entities`, `original_entity_relationships`, `events`, `evidence_records`, `event_trace_relationships`, and total `relationships`, along with accepted, rejected, invalid, and duplicate counts.

Both modes include:

- warnings grouped by their explicit message; and
- the names of output files produced.

`rejected.jsonl` records a source locator and validation/parse reason. It intentionally excludes raw rows; for invalid timestamps, it retains only the raw timestamp value. Records needing timestamp validation are still exported with a null normalized time and counted as invalid. Other rejected records are not silently discarded. A successful process exit does not imply the dataset is complete or that labels are ground truth.
