# TRUSTRAIL AI — Member 3 Data Pipeline

This project contains the defensive telemetry ingestion and normalization work for Member 3. It reads local CSV, JSON, or JSONL files, preserves source provenance and explicit IDs, validates records, and emits graph-ready entities, relationships, events, and evidence. It does not download datasets, access networks, or execute source files.

The exporter follows Member 2's initial graph/import contract, including the confirmed `SUPPORTED_BY` and `OBSERVED_ON` traceability edge directions. Neo4j import testing remains with Member 2.

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

Add `--synthetic` for synthetic input. Evidence status remains `observed`, `derived`, or `unconfirmed` and is kept separate from synthetic provenance.

## Export a split graph dataset

For source data already split into entity, relationship, event, and evidence CSVs:

```powershell
$env:PYTHONPATH = "src"
python -m trustrail_pipeline.cli ingest-graph `
  --entities C:\data\entities.csv `
  --relationships C:\data\relationships.csv `
  --events C:\data\events.csv `
  --evidence C:\data\evidence.csv `
  --output-dir data\processed\graph-fixture
```

The exporter preserves supplied IDs and property values, adds event trace links to `relationships.jsonl`, and sets `relationship_category` to `original_entity` or `event_trace`. Trace `OBSERVED_ON` records carry `endpoint_role: "source"` or `"target"`. Metadata reports both relationship counts separately.

Supported input formats are CSV, JSON Lines (`.jsonl` / `.ndjson`), and small JSON documents. JSON documents are limited to 16 MiB to avoid unbounded in-memory parsing. Use JSONL or CSV for larger sources. `--max-records` can limit a local test run.

Recognized input shapes:

- LANL-style network flow rows with `Time`, `SrcDevice`, and `DstDevice`.
- LANL-style host records with `EventID`, `Time`, and host/user/process fields.

Invalid rows are recorded in `rejected.jsonl`; errors reading the input file are surfaced. The pipeline does not silently drop malformed records.

## Outputs

- `events.jsonl` — normalized events and candidate Member 2 event fields.
- `entities.jsonl` — deduplicated entity records with `id`, `type`, and Boolean `synthetic`.
- `relationships.jsonl` — source relationships plus event-to-evidence and event-to-entity trace links, categorized separately.
- `evidence.jsonl` — source record, observed/ingested time, and provenance.
- `rejected.jsonl` — record locator and explicit validation/parsing error; invalid timestamps are preserved without copying the entire raw row.
- `metadata.json` — measured run counts, warnings, runtime, input size, and transform version.

Output records are deterministic for the same dataset ID, source record IDs, and input, except for run-time metadata. The bundled demo is illustrative synthetic data, not the separate 18-entity/17-relationship fixture Member 2 described. See [docs/ingestion_contract.md](docs/ingestion_contract.md) and [docs/troubleshooting.md](docs/troubleshooting.md).

## Validate

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

## TRUSTRAIL SOC frontend (Phase 2)

The React dashboard consumes the FastAPI `/api` contracts defined in `backend/app/main.py`.
The included demo API reads the repository's synthetic graph fixture; it does not contain
real telemetry or execute containment actions.

Install and start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

In another terminal, start the demo API:

```powershell
python -m pip install -r backend\requirements.txt
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Open `http://localhost:5173`. FastAPI documentation is available at
`http://127.0.0.1:8000/docs`.
