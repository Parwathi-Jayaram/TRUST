# Synthetic scenario policy

`python -m trustrail_pipeline.cli demo` writes a deterministic JSONL fixture for local testing. Its account, host, process, and network details are fictional and carry `evidence_status: "synthetic"` in all exported records.

The fixture exercises:

- a successful authentication event (`AUTHENTICATED_TO`);
- an explicit process-start event (`RUNS`); and
- a network flow (`COMMUNICATES_WITH`).

It does not claim a real incident, verified compromise, vulnerability, or ground-truth fraud/attack label. It does not create an application dependency or causal path without an explicit fixture record. Keep synthetic inputs and generated outputs separate from public-source data.
