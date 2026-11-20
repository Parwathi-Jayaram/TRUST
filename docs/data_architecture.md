# Data pipeline architecture

```text
Authorized local CSV / JSON / JSONL
    -> streaming reader
    -> source-shape and relationship-endpoint validation
    -> UTC normalization where source-time semantics are defensible
    -> preserve explicit IDs; generate deterministic IDs only when absent
    -> emit entities, events, evidence, and directed domain relationships
    -> add event-to-evidence and event-to-entity traceability links
    -> JSONL exports + metadata.json + rejected.jsonl
    -> Member 2-owned Neo4j importer
```

The pipeline is offline and read-only with respect to input files. CSV and JSONL are processed one record at a time. JSON documents are intentionally limited to 16 MiB and should be converted to JSONL for larger sources. A temporary SQLite index avoids retaining every deduplication key in Python memory; staged output files are replaced only after a successful run.

No relationship is created from shared identity, hostname, IP address, or time alone. The six supported domain relationships are validated against the Member 2 endpoint-type contract. `SUPPORTED_BY` and `OBSERVED_ON` are provisional traceability relationship names pending confirmation. The exporter does not connect to Neo4j; import transactions and batch rollback belong to Member 2's importer.
