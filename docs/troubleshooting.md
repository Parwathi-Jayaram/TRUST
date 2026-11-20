# Troubleshooting

## `Unsupported input format`

Use `.csv`, `.json`, `.jsonl`, or `.ndjson`, or pass `--format csv|json|jsonl`.

## `JSON document ... in-memory JSON limit`

The reader limits a single JSON document to 16 MiB. Convert a large array/object file to JSON Lines, or test a smaller authorized subset.

## Rows appear in `rejected.jsonl`

Check `reason`, `source_file`, and `record_locator`. Typical causes are malformed JSON, missing/unparseable timestamps, or an unrecognized row shape. The raw row is not copied into the rejection file.

## Timestamp is present but `event_time_utc` is null

Inspect `event_time_original` and `timestamp_semantics`. A naive local timestamp or small numeric source time is preserved but not guessed as UTC. Supply a documented source timezone/origin mapping before adding conversion behavior.

## No relationship was exported

Only explicit network flow, successful supported authentication, and process-start shapes currently create relationships. Failed authentication and logoff records remain events without `AUTHENTICATED_TO`. Missing endpoints are warnings, not guessed entities.

## Import fails with `No module named trustrail_pipeline`

From the project root, set `$env:PYTHONPATH = "src"` in PowerShell before running the CLI or tests.

## Dataset access or license is unclear

Do not retry through unofficial mirrors or download large files. Consult the official source page and [dataset licensing review](dataset_licensing.md); ask the provider when the reuse terms are ambiguous.
