# Data pipeline architecture

```text
Authorized local CSV / JSON / JSONL
    -> streaming reader
    -> source-shape validation
    -> UTC normalization where the source timezone is defensible
    -> deterministic event/entity/evidence IDs
    -> conservative relationship extraction
    -> deduplicated JSONL graph candidates
    -> measured run report and rejected-record report
    -> Member 2 contract review
```

The pipeline is offline and read-only with respect to input files. CSV and JSONL are processed one record at a time. JSON documents are intentionally limited to 16 MiB and should be converted to JSONL for larger sources. A temporary SQLite index avoids retaining every deduplication key in Python memory; staged output files are replaced only after a successful run.

No relationship is created from shared identity, hostname, IP address, or time alone. Current extraction supports LANL-style network flows (`COMMUNICATES_WITH`), successful authentication events (`AUTHENTICATED_TO`), and explicit process-start records (`RUNS`). Unsupported records are rejected with a reason rather than guessed into a graph.
