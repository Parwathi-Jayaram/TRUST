# Entity resolution policy

Entity IDs are deterministic hashes in a dataset namespace. A host name, account name, process name, or IP address is not treated as a globally unique identity.

- Preserve the source dataset namespace and raw display value where the source license and privacy policy allow it.
- Normalize IP syntax using the standard library, but treat the address as a time-dependent observation, not proof of asset ownership.
- Do not merge records solely because names look similar or because two records share an IP address.
- Do not infer identity from temporal proximity.
- Keep ambiguous matches separate; represent a candidate association only when explicit source evidence supports it and mark it as `derived`/unconfirmed.
- Duplicate event IDs are skipped idempotently. Records without a source record ID use file name plus row/line locator; exact duplicate-looking rows with different locators are not silently collapsed because they may be distinct events.
- Never store raw credentials. Use only public/de-identified or explicitly authorized sources.

Member 2 must confirm stable-key namespaces and graph uniqueness constraints before Neo4j ingestion.
