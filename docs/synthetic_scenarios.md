# Synthetic scenario policy

`python -m trustrail_pipeline.cli demo` writes a deterministic JSONL fixture for local testing. Its account, host, process, application, vulnerability, and incident details are fictional and carry `synthetic: true` or `is_synthetic: true`. Evidence status is separate and remains `observed`, `derived`, or `unconfirmed`.

The fixture exercises:

- a successful authentication event (`AUTHENTICATED_TO`);
- an explicit process-start event (`RUNS`);
- a network flow (`COMMUNICATES_WITH`);
- explicit dependency, vulnerability, and incident associations; and
- event-to-evidence (`SUPPORTED_BY`) and event-to-entity (`OBSERVED_ON`) traceability edges.

It does not claim a real incident, verified compromise, vulnerability, or ground-truth attack label. It is illustrative and does not reproduce the separate 18-entity/17-relationship fixture Member 2 described. Keep synthetic inputs and generated outputs separate from public-source data.
