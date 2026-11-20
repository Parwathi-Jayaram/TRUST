# TRUSTRAIL AI Member 3 — Phase 0

**Status:** Phase 0 reviewed; no real-source dataset has been downloaded. Member 2's initial graph contract and authorized synthetic fixture were received on 2026-11-20.

**Scope:** This document records source feasibility and data requirements. The current JSONL exporter contract is maintained in [ingestion_contract.md](ingestion_contract.md).

## 1. Member 3 responsibilities

Member 3 owns the defensive cybersecurity data-engineering foundation: evaluate authorized sources, preserve source provenance, parse and validate security records, normalize event formats, resolve entities conservatively, extract evidence-backed relationships, and produce reproducible graph-ready exports. Member 3 also documents data quality, coverage, licensing, synthetic scenarios, and limitations, and coordinates the graph-ingestion contract with Member 2.

The project is about graph analytics for threat hunting and blast-radius investigation. A suspicious record, shared IP, temporal association, vulnerability match, or synthetic scenario is not by itself proof of compromise or causation.

## 2. Minimum useful telemetry

Prioritize identity/authentication, endpoint/process, network-flow, and asset-inventory records. Alerts, vulnerability data, indicators, and application dependencies add context but should not be fabricated from unrelated observations.

| Category | Minimum fields | Graph use |
|---|---|---|
| Identity/authentication | event time, user/account identifier, source and destination host where available, event type, success/failure, source record ID | Identity-to-host investigation |
| Endpoint/process | event time, host, process ID/name, parent process where available, user, source record ID | Process and host relationships |
| Network flow | start time, source/destination asset or address, protocol, ports where available, duration, packets/bytes, source record ID | Communication relationships and timelines |
| Asset inventory | stable asset ID, asset type, hostname/address when known, observation time, criticality and its source | Blast-radius context |
| Security alert | alert ID, time, severity as supplied, linked entities/events, source | Investigation evidence |
| Vulnerability | asset ID, CVE, supplied severity/status, observation time, source | Exposure context, not proof of exploitation |
| Threat indicator | indicator type/value, source, retrieval and observation times, expiration/confidence when supplied | Time-bounded enrichment |
| Application dependency | source and target asset, dependency type, source/evidence | Service impact paths |

Do not ingest credentials, payloads, personal data, or confidential organizational telemetry without explicit authorization. Retain original values only where allowed and needed to reproduce transformations.

## 3. Source audit

Source and licensing details below are from the linked official pages checked on 2026-11-20. Dataset pages do not always publish a machine-readable license or total download size; those gaps are called out rather than inferred. Use a small, selected sample first. No download is authorized by this proposal.

| Source | Fit, format, and scale | Rights and limitations | Phase 0 decision |
|---|---|---|---|
| [LANL Unified Host and Network Dataset (2017)](https://csr.lanl.gov/data/2017/) | Best match for graph relationships: about 90 days of de-identified host events (JSON Lines) and network events (CSV), with authentication, process, host, and flow fields. Published page gives no total size; files are available by day and the page asks for intended-use information. | LANL marks the dataset CC0 1.0 and requires citation for publications. De-identification is not a guarantee of complete privacy; a source page notes some system-level values remain identifiable. The dataset does not promise ground-truth attack labels for every event. | **Recommended primary source**, subject to Member 1/2 review and verifying access to a minimal day/sample. Start with one day of host and network records; do not fetch all 90 days. |
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Labeled network flows and PCAPs, with timestamps, endpoint addresses/ports, protocols, and labels. Official page lists 5 daily captures totaling about 51.1 GB of PCAPs. Machine-learning CSVs are also offered, but their size is not stated on the page. | CIC's FAQ permits use/redistribution with dataset and paper citation; verify the dataset page and attribution before redistribution. Five-day 2017 testbed traffic and attack labels do not model general enterprise behavior or user identity. | **Supporting option** for labeled network-flow examples. Prefer a small CSV subset; avoid full PCAPs for the demo. |
| [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html), [AWS Open Data entry](https://registry.opendata.aws/cse-cic-ids2018/) | Network traffic, host logs, and 80 extracted network features; seven attack scenarios. Public S3 access is documented, but the official pages do not state a total dataset size. The source describes hundreds of machines, so treat the full corpus as large. | AWS points to CIC for license/documentation; CIC's general FAQ requires citations for reuse/redistribution. The dataset is a generated testbed, not live enterprise prevalence. | **Defer full use.** Consider only a documented small sample if LANL lacks a required field. Do not download the bucket during Phase 0. |
| [CTU-13](https://www.stratosphereips.org/datasets-ctu13) | Thirteen labeled botnet scenarios; bidirectional labeled NetFlow files, PCAPs, and other scenario files. The full archive is listed as 1.9 GB; individual scenarios are available. | The official page requests a paper citation but does not state a clear reuse license. Ask the provider for permission terms before redistribution. Full PCAP/background traffic is not available for privacy reasons. The archive also lists original executable files, which the project does not need and must not execute. | **Optional supporting source** for labeled communication-flow examples only, after licensing review. Use scenario flow files, not executables. |
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | Network intrusion records: 2,540,044 CSV rows across four files, 49 features, and nine attack categories; raw PCAPs total about 100 GB. The page also lists a much smaller 175,341-row training and 82,332-row testing split. | The official page grants free academic research use; commercial use requires agreement with the authors. Citation is required. Network-focused labels do not provide the identity/process context needed for the primary graph use case. | **Not selected for the initial demo.** Use only if academic-use terms fit and comparative model data is required. |
| [CIC datasets index](https://www.unb.ca/cic/datasets/index.html) | A catalog of distinct datasets, not one uniform dataset or format. Sizes and fields vary by dataset. | CIC's FAQ says use and redistribution require citations; confirm the selected dataset's page and attribution. | Select a named dataset (CIC-IDS2017 or CSE-CIC-IDS2018), not the catalog generically. |
| [MITRE ATT&CK](https://attack.mitre.org/), [official STIX data](https://github.com/mitre-attack/attack-stix-data), [terms](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) | Structured tactics/techniques and relationships; STIX data is available from the official repository. It is not endpoint or network telemetry. | MITRE grants a royalty-free license for research, development, and commercial use subject to reproducing its copyright designation and license statement. | **Supporting enrichment only.** Store technique references as context; never infer that a technique occurred from a technique match. |
| [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) | Current vulnerability catalog with CSV, JSON, and schema links. | Catalog data is CC0 1.0; linked third-party material has its own terms. KEV membership indicates CISA tracks exploitation of a vulnerability, not that a specific project asset was exploited. | **Supporting enrichment only**, joined to an explicitly observed/synthetic asset-CVE record; record retrieval time. |
| [NVD](https://nvd.nist.gov/), [data feeds](https://nvd.nist.gov/vuln/data-feeds) | CVE and vulnerability metadata for enrichment; use a targeted API/feed query rather than a full historical dump. NVD's current feed documentation is client-rendered, so exact feed size and terms must be rechecked before bulk use. | Check NIST/NVD terms and any third-party CVE data conditions before mirroring. Severity and descriptions are vulnerability metadata, not exploitation evidence. | **Optional supporting enrichment.** Defer until a concrete asset/CVE use case and size/terms are reviewed. |

### Source recommendation

Use the LANL Unified Host and Network Dataset as the **primary feasibility candidate** because it is the only suggested source that directly combines identity/process host events with network flows and has an explicit CC0 statement. First verify a minimal sample is accessible and inspect its schemas; its page gives no overall size, so do not estimate a total or download the full 90 days. If its data is unavailable or unsuitable, reassess with Member 1 rather than silently switching sources.

Use ATT&CK and CISA KEV as narrowly scoped, time-stamped contextual enrichment. Consider a small CIC-IDS2017 labeled-flow sample only if additional labeled network events are needed and the file size is known before download. CTU-13, CSE-CIC-IDS2018, UNSW-NB15, and bulk NVD data remain optional and gated on a specific need, size review, and license check.

### Keep synthetic rather than externally sourced

- Stable demo identities, assets, dependencies, and criticality values that do not exist in the selected public telemetry.
- Explicit investigation narratives that connect identity, host, process, communication, application, and alert records.
- Controlled benign and suspicious scenarios used to demonstrate graph paths.
- Ground-truth labels for generated records, stored separately from observed public-data labels.

Every synthetic record and relationship must carry a Boolean synthetic-origin field and a scenario/source identifier. Keep that flag separate from `evidence_status`, which records whether an assertion is observed, derived, or unconfirmed. Do not merge synthetic and sourced records without preserving each record's origin. Do not invent public-data labels, indicators, causal links, or incident outcomes.

## 4. Preliminary data requirements and pipeline

### Requirements matrix

| Requirement | Needed for | Preferred source | Phase 0 status |
|---|---|---|---|
| User/account ↔ host authentication events with time and outcome | Identity investigation | LANL host events | Candidate; verify sample schema |
| Host ↔ host/network communication with time and protocol | Graph paths and timeline | LANL network events | Candidate; verify identifiers and timestamps |
| Process execution and parent/child evidence | Endpoint pivots | LANL host events | Candidate; verify event coverage |
| Asset type/criticality | Blast-radius prioritization | Synthetic inventory initially | Synthetic until an authorized inventory source is agreed |
| Alerts and source-record evidence | Explainable investigation | Synthetic demo alerts initially | Must not be presented as real incidents |
| Asset ↔ CVE context | Exposure paths | Synthetic asset-CVE mappings + CISA KEV/NVD context | Requires explicit matching input; CVE presence alone is not exploitation |
| Application/service dependencies | Downstream impact paths | Synthetic inventory initially | Do not infer from shared names or traffic alone |
| Stable IDs, event time, provenance | Reproducible graph ingestion | Every source | Required for every accepted record |

### Preliminary architecture

`Authorized/public/synthetic source` → immutable raw-file manifest and checksum where available → chunked CSV/JSONL parser → schema/type validation → rejected-record report (never silently drop) → normalized event layer retaining source fields → conservative entity resolution → evidence-backed relationships → graph-ready CSV/JSONL export → Member 2-owned Neo4j ingestion.

Keep raw data unchanged where permitted. Track source name/version, URL, file, retrieval time, license/citation, checksum where useful, parser and transform versions, and rejection reasons. Use chunked processing for large files. Do not run network scans, contact indicators, or execute downloaded malware.

### Initial normalized event example

This illustrative shape follows Member 2's initial implementation contract; see [ingestion_contract.md](ingestion_contract.md) for the exporter fields:

```json
{
  "event_id": "EVT-001",
  "event_type": "authentication",
  "event_time": "2026-01-15T10:20:30Z",
  "event_time_original": "2026-01-15T10:20:30Z",
  "timestamp_semantics": "iso8601",
  "ingested_at": "<generated-at-ingestion>",
  "source_system": "<source-system>",
  "source_record_id": "<source-record-id>",
  "severity": null,
  "description": "Synthetic successful authentication",
  "evidence_id": "EVD-001",
  "evidence_status": "observed",
  "is_synthetic": true
}
```

The example is illustrative only; its IDs and values are not an extracted real record. Preserve original timestamps and source fields. Do not label an unknown timezone as UTC; keep its raw value, leave normalized `event_time` unset, and report it for validation.

### Initial entity and relationship plan

- Entity candidates: `User`, `Host`, `IPAddress`, `Process`, `Application`, `Alert`, `Vulnerability`, and `ThreatIndicator`.
- Extract `AUTHENTICATED_TO` only from an explicit authentication event; include outcome, timestamp, and event evidence.
- Extract `COMMUNICATES_WITH` only from an explicit network flow; preserve direction, protocol, and time.
- Extract process relationships only from explicit process/parent-process fields.
- Add `DEPENDS_ON` only from an explicit inventory/dependency record or labeled synthetic fixture.
- Add asset-to-CVE context only from an explicit vulnerability/inventory match; do not infer exploitation.
- Preserve ambiguous identity associations as unconfirmed possibilities. Do not merge records solely because of a shared IP, hostname, username, or time window. Every relationship must reference evidence and retain its observed, derived, or unconfirmed status separately from its synthetic-origin flag.

### Member 2 coordination contract

Member 2 supplied an initial implementation contract on 2026-11-20. It calls for `Entity` plus type-specific labels, `SecurityEvent` and `Evidence` nodes, exact supplied IDs, JSONL exports, and `MERGE`-based import keyed by entity/event/evidence/relationship IDs. The domain relationships are `AUTHENTICATED_TO`, `COMMUNICATES_WITH`, `RUNS`, `DEPENDS_ON`, `HAS_VULNERABILITY`, and `INVOLVES`, with source-to-target direction preserved.

Member 2 confirmed the event-to-evidence and event-to-entity directions as `SUPPORTED_BY` and `OBSERVED_ON`. `OBSERVED_ON` retains `endpoint_role` as `source` or `target`. The exporter marks these generated links with `relationship_category: "event_trace"` and preserves the original CSV edges with `relationship_category: "original_entity"`.

The initial contract separates the Boolean synthetic-origin field from evidence status (`observed`, `derived`, or `unconfirmed`), keeps `event_time`, `observed_at`, and `ingested_at` distinct, and requires invalid timestamps to remain unset while retaining their raw value for validation. Neo4j batch size, parameterized Cypher, transaction rollback, and importer error handling remain Member 2's importer responsibilities. Do not assume NIX's transaction-risk module is the graph schema for this cybersecurity task.

## 5. Remaining validation work

The authorized synthetic fixture has been exported locally. Its 18 entities, 17 original relationships, 17 events, and 17 evidence records passed export and reference checks. Event trace links are separated by category and preserve source/target endpoint roles. Member 2's Neo4j test import, repeated-import test, and graph-level traceability checks remain pending. No real-source dataset has been downloaded or validated.

## 6. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Dataset terms differ from expected or are unclear | Unauthorized reuse/redistribution | Record the exact dataset page and terms; obtain clarification before redistribution |
| LANL sample is inaccessible or lacks required data | Primary-source plan blocked | Test only an approved minimal sample; return to source review if blocked |
| Large PCAP/log download | Storage/time cost | Set an explicit byte cap; use one-day or CSV subsets; no bulk download without approval |
| Schema mismatch with Member 2 | Exports cannot be ingested | Member 2 approves graph labels, IDs, timestamps, and evidence fields first |
| Correlation is misrepresented as causation | Misleading threat paths | Preserve evidence status and uncertainty; only derive documented relationships |
| Synthetic data appears real | False investigation claims | Mark synthetic status at event, entity, and relationship level; separate labels |
| Stale or unverified enrichment | Incorrect risk context | Store source and retrieval time; check expiry/freshness; treat as context only |
| Sensitive values in example telemetry | Privacy exposure | Use public/de-identified or authorized sample data; avoid credentials and unnecessary identifiers |

## 7. Remaining Phase 0/data gates

- Member 1 reviews the source recommendation, dataset limitations, licensing/attribution, and download-size constraints.
- Member 2 supplied the initial graph/import contract and confirmed `SUPPORTED_BY` / `OBSERVED_ON` trace links; Neo4j import validation remains pending.
- The authorized synthetic fixture is used only for contract/integration testing. The team must agree on any real-data source and maximum download size before downloading it.
- Required versus optional telemetry, timestamp semantics, synthetic-data policy, and provenance rules are accepted.
- No real dataset has been downloaded or validated; synthetic fixture results are not evidence of real-world detection performance.

## Official source links

- [CIC dataset catalog](https://www.unb.ca/cic/datasets/index.html)
- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) and [AWS Open Data Registry](https://registry.opendata.aws/cse-cic-ids2018/)
- [CTU-13](https://www.stratosphereips.org/datasets-ctu13)
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [LANL Unified Host and Network Dataset](https://csr.lanl.gov/data/2017/)
- [MITRE ATT&CK terms](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) and [official STIX data](https://github.com/mitre-attack/attack-stix-data)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [catalog license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)
- [NVD data feeds](https://nvd.nist.gov/vuln/data-feeds)
