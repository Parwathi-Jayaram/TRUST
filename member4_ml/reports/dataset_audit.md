# TRUSTRAIL AI — Member 4 Dataset Audit Report (Phase 1)

## 1. Synthetic TRUSTRAIL Dataset (Dataset A) — Member 3 events.jsonl

- Source: `C:\Users\parwa\OneDrive\Desktop\hackfront\TRUST\data\demo-run\processed\events.jsonl`
- Rows: 6
- Columns: 24
- Numeric columns: ['attr_EventID', 'attr_DstBytes', 'attr_DstPackets', 'attr_DstPort', 'attr_Duration', 'attr_Protocol', 'attr_SrcBytes', 'attr_SrcPackets', 'attr_SrcPort']
- Categorical columns: ['description', 'event_id', 'event_time', 'event_time_original', 'event_type', 'evidence_id', 'evidence_status', 'ingested_at', 'is_synthetic', 'severity', 'source_record_id', 'source_system', 'timestamp_semantics', 'attr_ParentProcessName', 'attr_ProcessID']
- Missing values: {'description': 2, 'event_id': 0, 'event_time': 0, 'event_time_original': 0, 'event_type': 0, 'evidence_id': 0, 'evidence_status': 0, 'ingested_at': 0, 'is_synthetic': 0, 'severity': 6, 'source_record_id': 0, 'source_system': 0, 'timestamp_semantics': 0, 'attr_EventID': 5, 'attr_ParentProcessName': 5, 'attr_ProcessID': 5, 'attr_DstBytes': 5, 'attr_DstPackets': 5, 'attr_DstPort': 5, 'attr_Duration': 5, 'attr_Protocol': 5, 'attr_SrcBytes': 5, 'attr_SrcPackets': 5, 'attr_SrcPort': 5}
- Duplicate rows: 0
- Memory usage: 0.005 MB

### Schema warnings
- [synthetic_events.jsonl] Identifier columns present: ['event_id', 'source_record_id']
- [synthetic_events.jsonl] Missing values: {'description': 2, 'severity': 6, 'attr_EventID': 5, 'attr_ParentProcessName': 5, 'attr_ProcessID': 5, 'attr_DstBytes': 5, 'attr_DstPackets': 5, 'attr_DstPort': 5, 'attr_Duration': 5, 'attr_Protocol': 5, 'attr_SrcBytes': 5, 'attr_SrcPackets': 5, 'attr_SrcPort': 5}

### Column data types
- description: object
- event_id: object
- event_time: object
- event_time_original: object
- event_type: object
- evidence_id: object
- evidence_status: object
- ingested_at: object
- is_synthetic: bool
- severity: object
- source_record_id: object
- source_system: object
- timestamp_semantics: object
- attr_EventID: float64
- attr_ParentProcessName: object
- attr_ProcessID: object
- attr_DstBytes: float64
- attr_DstPackets: float64
- attr_DstPort: float64
- attr_Duration: float64
- attr_Protocol: float64
- attr_SrcBytes: float64
- attr_SrcPackets: float64
- attr_SrcPort: float64

### Usage in Member 4
- Used for integration testing, I/O format validation, and pipeline smoke tests.
- All records carry `is_synthetic: true`; never presented as real-world performance.
- Not used to train production models or claim real detection accuracy.

## 2. UNSW-NB15 Dataset (Dataset B)

- Status: **Not available** — download blocked.
- Official source: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- SharePoint download requires authentication; Member 1 approval needed.
- Expected files: `UNSW_NB15_training-set.csv` (175,341 rows), `UNSW_NB15_testing-set.csv` (82,332 rows).
- Nine attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms.
- Will be used for supervised binary + multiclass training once downloaded and approved.
- Academic use only; commercial use requires author agreement. Citation required.

## 3. Leakage Prevention Checklist
- Binary classification target: `label` (never `attack_cat` as input).
- Multiclass classification target: `attack_cat` (never `label` as input).
- Identifier columns (`id`, `event_id`, `source_record_id`) excluded from model features.
- Preprocessing fitted only on training data; applied to validation/test.
- No resampling applied to the test set.

## 4. Recommendations
- Proceed with Phase 2 preprocessing using the Member 3 synthetic events.jsonl schema.
- Download UNSW-NB15 only after Member 1 confirms academic-use approval.
- Keep synthetic test outcomes separate from public-dataset evaluation results.