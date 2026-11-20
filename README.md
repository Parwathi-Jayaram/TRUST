# TRUSTRAIL AI — Member 3 Data Pipeline

This project contains the defensive telemetry ingestion and normalization work for Member 3. It reads local CSV, JSON, or JSONL files, preserves source provenance, validates records, and emits candidate graph-ready events, entities, relationships, and evidence. It does not download datasets, access networks, or execute source files.

The Member 2 graph fields are provisional: their brief explicitly describes the schema as a starting proposal. Confirm the final contract against representative source records before production ingestion.

## Requirements

- Python 3.10 or later
- Python standard library only

No raw datasets or real customer telemetry are included.

## Run a deterministic synthetic demo

From the repository root in PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m trustrail_pipeline.cli demo --output-dir data\demo-run
```

The command writes a synthetic JSONL input under `data\demo-run\input` and graph-ready exports under `data\demo-run\processed`. All events, entities, relationships, and evidence are marked synthetic.

## Ingest a local file

```powershell
$env:PYTHONPATH = "src"
python -m trustrail_pipeline.cli ingest `
  --input C:\data\approved-events.jsonl `
  --output-dir data\processed `
  --dataset-id approved-dataset-v1 `
  --source-system approved-source `
  --version 1 `
  --license "record the source license" `
  --evidence-status observed
```

Supported input formats are CSV, JSON Lines (`.jsonl` / `.ndjson`), and small JSON documents. JSON documents are limited to 16 MiB to avoid unbounded in-memory parsing. Use JSONL or CSV for larger sources. `--max-records` can limit a local test run.

Recognized input shapes:

- LANL-style network flow rows with `Time`, `SrcDevice`, and `DstDevice`.
- LANL-style host records with `EventID`, `Time`, and host/user/process fields.

Invalid rows are recorded in `rejected.jsonl`; errors reading the input file are surfaced. The pipeline does not silently drop malformed records.

## Outputs

- `events.jsonl` — normalized events and candidate Member 2 event fields.
- `entities.jsonl` — deduplicated entity records.
- `relationships.jsonl` — evidence-backed candidate graph relationships.
- `evidence.jsonl` — source record, observed/ingested time, and provenance.
- `rejected.jsonl` — record locator and explicit validation/parsing error, without copying raw row values.
- `report.json` — measured run counts, warnings, runtime, input size, and transform version.

Output records are deterministic for the same dataset ID, source record IDs, and input. `ingestion_time` and run metrics reflect the actual run. See [docs/ingestion_contract.md](docs/ingestion_contract.md) and [docs/troubleshooting.md](docs/troubleshooting.md).

## Validate

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```
