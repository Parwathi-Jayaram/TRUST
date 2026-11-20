# Provenance and evidence policy

Every event and relationship must be traceable to a source record. Explicit event, evidence, relationship, and endpoint IDs are preserved.

Retain the dataset ID, source system, source record ID, input filename, source version/URL/license when provided, evidence ID/status, source time, ingestion time, and transform version. `metadata.json` records input format/size, elapsed time, measured accepted/rejected/duplicate/invalid counts, and warning counts.

`evidence_status` retains `observed`, `derived`, or `unconfirmed`; it is separate from the Boolean synthetic-origin field. `observed` means directly represented in an input record; `derived` means deterministically inferred from explicit source fields under a documented rule; `unconfirmed` remains unconfirmed. Do not convert an unconfirmed relationship to observed or invent confidence values.

Do not treat correlation as causation, ATT&CK technique context as proof of an attack, KEV membership as proof an asset was exploited, or a suspicious event as a confirmed incident. Keep source record and evidence IDs attached to every candidate graph relationship. Event-to-evidence and event-to-entity trace edges use Member 2's confirmed `SUPPORTED_BY` and `OBSERVED_ON` types.

Raw input files are read-only and are not copied into generated output. Rejected-record output omits raw row contents to avoid accidental disclosure; invalid timestamps are retained as a field-level value so the record can be reviewed without copying the entire row.
