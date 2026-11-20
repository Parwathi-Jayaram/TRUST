# Data source register

No public dataset is bundled or downloaded by this project.

| Dataset/source | Intended use | Status | Size and access gate |
|---|---|---|---|
| LANL Unified Host and Network Dataset (2017) | Primary feasibility candidate for host/authentication and network-flow graph relationships | Phase 0 approved as a candidate; inspect actual schemas before mapping | Official page publishes no total size. Request/inspect only an approved daily sample; do not download all 90 days. |
| CIC-IDS2017 | Optional labeled network-flow examples | Supporting option only | Official page lists 51.1 GB of daily PCAP captures; prefer a known-size CSV subset. |
| CSE-CIC-IDS2018 | Optional host/network fields if LANL lacks a required field | Deferred | Full size is not stated on the official pages; no full-bucket download. |
| CTU-13 | Optional labeled bidirectional flows | Deferred pending reuse-term confirmation | Official archive listed as 1.9 GB; use only selected flow files, never executables. |
| UNSW-NB15 | Optional comparison dataset | Not selected | Raw PCAPs total about 100 GB; academic-use grant only, commercial use requires author agreement. |
| MITRE ATT&CK | Technique context | Optional enrichment | Use official STIX data and reproduce MITRE's required copyright/license statement. |
| CISA KEV | Current vulnerability context | Optional enrichment | Use the official CSV/JSON; preserve retrieval time and CC0 notice context. |
| NVD | CVE metadata | Deferred | Query only a demonstrated need; confirm current feed size and terms before bulk retrieval. |

Official source links and caveats are maintained in [member3-phase0.md](member3-phase0.md). Dataset selection does not authorize redistribution; retain citations and source license terms with any reused data.
