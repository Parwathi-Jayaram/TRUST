"""Export an existing entity/event/evidence graph dataset from separate CSVs."""

from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .normalization import RELATIONSHIP_ENDPOINT_TYPES, normalize_timestamp, stable_id
from .readers import ReadResult, iter_records


OUTPUT_NAMES = (
    "entities.jsonl",
    "relationships.jsonl",
    "events.jsonl",
    "evidence.jsonl",
    "rejected.jsonl",
)
METADATA_NAME = "metadata.json"
ENTITY_TYPES = {
    "user",
    "host",
    "server",
    "application",
    "ip",
    "ipaddress",
    "process",
    "vulnerability",
    "incident",
}
EVIDENCE_STATUSES = {"observed", "derived", "unconfirmed"}


def _read_csv(path: Path) -> tuple[list[ReadResult], list[ReadResult]]:
    if not path.is_file():
        raise FileNotFoundError(f"input file does not exist: {path}")
    rows: list[ReadResult] = []
    errors: list[ReadResult] = []
    for result in iter_records(path, "csv"):
        if result.error:
            errors.append(result)
        else:
            rows.append(result)
    return rows, errors


def _required(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if value is None or not str(value).strip():
        raise ValueError(f"{field} is required")
    return str(value)


def _optional(record: dict[str, Any], field: str) -> Any:
    value = record.get(field)
    if value is None or (isinstance(value, str) and value == ""):
        return None
    return value


def _boolean(record: dict[str, Any], field: str) -> bool:
    value = _required(record, field)
    normalized = value.strip().casefold()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise ValueError(f"{field} must be a Boolean value")


def _canonical_type(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized in {"ipaddress", "ip_address"}:
        return "ip"
    return normalized


def _rejection(
    source_file: str,
    locator: str,
    reason: str,
    *,
    source_record_id: str | None = None,
    raw_timestamp: str | None = None,
    recoverable: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source_file": source_file,
        "record_locator": locator,
        "source_record_id": source_record_id,
        "reason": reason,
        "recoverable": recoverable,
    }
    if raw_timestamp is not None:
        result["raw_timestamp"] = raw_timestamp
    return result


def _event_trace_status(statuses: list[str]) -> str:
    if "unconfirmed" in statuses:
        return "unconfirmed"
    if "derived" in statuses:
        return "derived"
    return "observed" if statuses else "derived"


def _trace_relationship(
    event: dict[str, Any],
    target_id: str,
    relationship_type: str,
    evidence_status: str,
    *,
    endpoint_role: str | None = None,
) -> dict[str, Any]:
    relationship_id = stable_id(
        "relationship",
        "event-trace",
        event["event_id"],
        relationship_type,
        target_id,
        endpoint_role or "",
    )
    relationship = {
        "relationship_id": relationship_id,
        "source_id": event["event_id"],
        "target_id": target_id,
        "relationship_type": relationship_type,
        "relationship_category": "event_trace",
        "evidence_status": evidence_status,
        "event_id": event["event_id"],
        "is_synthetic": event["is_synthetic"],
    }
    if endpoint_role is not None:
        relationship["endpoint_role"] = endpoint_role
    return relationship


def run_graph_csv_export(
    *,
    entities_path: str | Path,
    relationships_path: str | Path,
    events_path: str | Path,
    evidence_path: str | Path,
    output_dir: str | Path,
    dataset_id: str = "trustrail-member2-synthetic-v1",
) -> dict[str, Any]:
    """Preserve a split CSV graph fixture and add explicit event trace links."""
    paths = {
        "entities": Path(entities_path),
        "relationships": Path(relationships_path),
        "events": Path(events_path),
        "evidence": Path(evidence_path),
    }
    raw_rows: dict[str, list[ReadResult]] = {}
    rejected: list[dict[str, Any]] = []
    records_read = 0
    for table, path in paths.items():
        rows, errors = _read_csv(path)
        raw_rows[table] = rows
        records_read += len(rows) + len(errors)
        for error in errors:
            rejected.append(_rejection(path.name, error.locator, error.error or "invalid CSV row"))

    duplicates_skipped = 0
    invalid_timestamps = 0
    warning_counts: Counter[str] = Counter()
    entities: dict[str, dict[str, Any]] = {}
    for result in raw_rows["entities"]:
        record = result.record or {}
        try:
            entity_id = _required(record, "id")
            entity_type = _required(record, "type")
            if _canonical_type(entity_type) not in ENTITY_TYPES:
                raise ValueError(f"unsupported entity type: {entity_type}")
            if entity_id in entities:
                duplicates_skipped += 1
                rejected.append(
                    _rejection(
                        paths["entities"].name,
                        result.locator,
                        f"duplicate entity id: {entity_id}",
                        source_record_id=entity_id,
                        recoverable=True,
                    )
                )
                continue
            entity = {
                "id": entity_id,
                "type": entity_type,
                "synthetic": _boolean(record, "synthetic"),
            }
            for field in ("name", "criticality"):
                value = _optional(record, field)
                if value is not None:
                    entity[field] = value
            entities[entity_id] = entity
        except ValueError as error:
            rejected.append(
                _rejection(paths["entities"].name, result.locator, str(error), source_record_id=record.get("id"))
            )

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    events: dict[str, dict[str, Any]] = {}
    for result in raw_rows["events"]:
        record = result.record or {}
        try:
            event_id = _required(record, "event_id")
            if event_id in events:
                duplicates_skipped += 1
                rejected.append(
                    _rejection(
                        paths["events"].name,
                        result.locator,
                        f"duplicate event id: {event_id}",
                        source_record_id=event_id,
                        recoverable=True,
                    )
                )
                continue
            event_time, original_time, semantics = normalize_timestamp(record.get("event_time"))
            event = {
                "event_id": event_id,
                "event_type": _required(record, "event_type"),
                "event_time": event_time,
                "event_time_original": original_time,
                "timestamp_semantics": semantics,
                "severity": _optional(record, "severity"),
                "description": _optional(record, "description"),
                "evidence_id": _required(record, "evidence_id"),
                "is_synthetic": _boolean(record, "is_synthetic"),
                "source_entity_id": _required(record, "source_entity_id"),
                "target_entity_id": _required(record, "target_entity_id"),
                "ingested_at": started_at,
            }
            if event_time is None:
                invalid_timestamps += 1
                reason = f"event timestamp requires validation: {semantics}"
                warning_counts[reason] += 1
                rejected.append(
                    _rejection(
                        paths["events"].name,
                        result.locator,
                        reason,
                        source_record_id=event_id,
                        raw_timestamp=original_time,
                        recoverable=True,
                    )
                )
            events[event_id] = event
        except ValueError as error:
            rejected.append(
                _rejection(
                    paths["events"].name,
                    result.locator,
                    str(error),
                    source_record_id=record.get("event_id"),
                )
            )

    evidence: dict[str, dict[str, Any]] = {}
    for result in raw_rows["evidence"]:
        record = result.record or {}
        try:
            evidence_id = _required(record, "evidence_id")
            if evidence_id in evidence:
                duplicates_skipped += 1
                rejected.append(
                    _rejection(
                        paths["evidence"].name,
                        result.locator,
                        f"duplicate evidence id: {evidence_id}",
                        source_record_id=evidence_id,
                        recoverable=True,
                    )
                )
                continue
            observed_at, original_time, semantics = normalize_timestamp(record.get("observed_at"))
            item = {
                "evidence_id": evidence_id,
                "event_id": _required(record, "event_id"),
                "source_system": _required(record, "source_system"),
                "source_record_id": _required(record, "source_record_id"),
                "observed_at": observed_at,
                "observed_at_original": original_time,
                "observed_at_timestamp_semantics": semantics,
                "description": _optional(record, "description"),
                "is_synthetic": _boolean(record, "is_synthetic"),
                "ingested_at": started_at,
            }
            if observed_at is None:
                invalid_timestamps += 1
                reason = f"evidence timestamp requires validation: {semantics}"
                warning_counts[reason] += 1
                rejected.append(
                    _rejection(
                        paths["evidence"].name,
                        result.locator,
                        reason,
                        source_record_id=evidence_id,
                        raw_timestamp=original_time,
                        recoverable=True,
                    )
                )
            evidence[evidence_id] = item
        except ValueError as error:
            rejected.append(
                _rejection(
                    paths["evidence"].name,
                    result.locator,
                    str(error),
                    source_record_id=record.get("evidence_id"),
                )
            )

    invalid_event_ids: set[str] = set()
    for event_id, event in events.items():
        if event["source_entity_id"] not in entities or event["target_entity_id"] not in entities:
            invalid_event_ids.add(event_id)
            rejected.append(
                _rejection(
                    paths["events"].name,
                    f"event:{event_id}",
                    "event source_entity_id or target_entity_id is not present in entities.csv",
                    source_record_id=event_id,
                )
            )
        item = evidence.get(event["evidence_id"])
        if item is None or item["event_id"] != event_id:
            invalid_event_ids.add(event_id)
            rejected.append(
                _rejection(
                    paths["events"].name,
                    f"event:{event_id}",
                    "event evidence_id does not resolve to matching evidence.csv record",
                    source_record_id=event_id,
                )
            )
    for evidence_id, item in evidence.items():
        if item["event_id"] not in events or item["event_id"] in invalid_event_ids:
            rejected.append(
                _rejection(
                    paths["evidence"].name,
                    f"evidence:{evidence_id}",
                    "evidence event_id does not resolve to a valid events.csv record",
                    source_record_id=evidence_id,
                )
            )
    for event_id in invalid_event_ids:
        events.pop(event_id, None)

    original_relationships: dict[str, dict[str, Any]] = {}
    statuses_by_event: dict[str, list[str]] = {}
    for result in raw_rows["relationships"]:
        record = result.record or {}
        try:
            relationship_id = _required(record, "relationship_id")
            source_id = _required(record, "source_id")
            target_id = _required(record, "target_id")
            relationship_type = _required(record, "relationship_type")
            evidence_status = _required(record, "evidence_status")
            event_id = _required(record, "event_id")
            if evidence_status not in EVIDENCE_STATUSES:
                raise ValueError(f"unsupported evidence_status: {evidence_status}")
            if relationship_type not in RELATIONSHIP_ENDPOINT_TYPES:
                raise ValueError(f"unsupported relationship type: {relationship_type}")
            if relationship_id in original_relationships:
                duplicates_skipped += 1
                rejected.append(
                    _rejection(
                        paths["relationships"].name,
                        result.locator,
                        f"duplicate relationship_id: {relationship_id}",
                        source_record_id=relationship_id,
                        recoverable=True,
                    )
                )
                continue
            if source_id not in entities or target_id not in entities:
                raise ValueError("relationship endpoint ID is not present in entities.csv")
            if event_id not in events:
                raise ValueError("relationship event_id is not present in valid events.csv records")
            allowed_source, allowed_target = RELATIONSHIP_ENDPOINT_TYPES[relationship_type]
            source_type = _canonical_type(entities[source_id]["type"])
            target_type = _canonical_type(entities[target_id]["type"])
            if source_type not in allowed_source or target_type not in allowed_target:
                raise ValueError(
                    f"{relationship_type} has unsupported endpoint types {source_type} -> {target_type}"
                )
            relationship = {
                "relationship_id": relationship_id,
                "source_id": source_id,
                "target_id": target_id,
                "relationship_type": relationship_type,
                "relationship_category": "original_entity",
                "evidence_status": evidence_status,
                "event_id": event_id,
                "is_synthetic": _boolean(record, "is_synthetic"),
            }
            original_relationships[relationship_id] = relationship
            statuses_by_event.setdefault(event_id, []).append(evidence_status)
        except ValueError as error:
            rejected.append(
                _rejection(
                    paths["relationships"].name,
                    result.locator,
                    str(error),
                    source_record_id=record.get("relationship_id"),
                )
            )

    trace_status_by_event: dict[str, str] = {}
    for event_id, event in events.items():
        status = _event_trace_status(statuses_by_event.get(event_id, []))
        trace_status_by_event[event_id] = status
        event["evidence_status"] = status
        evidence_record = evidence.get(event["evidence_id"])
        if evidence_record is not None:
            evidence_record["evidence_status"] = status

    trace_relationships: list[dict[str, Any]] = []
    valid_events = sorted(events.values(), key=lambda event: event["event_id"])
    for event in valid_events:
        status = trace_status_by_event[event["event_id"]]
        trace_relationships.append(
            _trace_relationship(event, event["evidence_id"], "SUPPORTED_BY", status)
        )
        trace_relationships.extend(
            _trace_relationship(
                event,
                entity_id,
                "OBSERVED_ON",
                status,
                endpoint_role=role,
            )
            for role, entity_id in (
                ("source", event["source_entity_id"]),
                ("target", event["target_entity_id"]),
            )
        )

    entities_output = list(entities.values())
    relationships_output = [
        *original_relationships.values(),
        *trace_relationships,
    ]
    events_output = valid_events
    evidence_output = [
        item
        for item in evidence.values()
        if item["event_id"] in events
    ]
    records_accepted = (
        len(entities_output)
        + len(original_relationships)
        + len(events_output)
        + len(evidence_output)
    )
    finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    input_files = {
        table: {"name": path.name, "size_bytes": path.stat().st_size}
        for table, path in paths.items()
    }
    counts = {
        "records_read": records_read,
        "records_accepted": records_accepted,
        "records_rejected": sum(not item["recoverable"] for item in rejected),
        "invalid_records": len(rejected),
        "duplicates_skipped": duplicates_skipped,
        "timestamps_unresolved": invalid_timestamps,
        "entities": len(entities_output),
        "original_entity_relationships": len(original_relationships),
        "event_trace_relationships": len(trace_relationships),
        "relationships": len(relationships_output),
        "events": len(events_output),
        "evidence_records": len(evidence_output),
    }
    metadata = {
        "dataset_id": dataset_id,
        "source_systems": sorted({item["source_system"] for item in evidence_output}),
        "input_files": input_files,
        "transform_version": "0.2.0",
        "started_at": started_at,
        "finished_at": finished_at,
        "counts": counts,
        "warning_counts": dict(sorted(warning_counts.items())),
        "outputs": [*OUTPUT_NAMES, METADATA_NAME],
    }
    output_records = {
        "entities.jsonl": entities_output,
        "relationships.jsonl": relationships_output,
        "events.jsonl": events_output,
        "evidence.jsonl": evidence_output,
        "rejected.jsonl": rejected,
    }

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="trustrail-graph-csv-", dir=destination) as temp_dir:
        temp_path = Path(temp_dir)
        for name, records in output_records.items():
            with (temp_path / name).open("w", encoding="utf-8", newline="\n") as stream:
                for record in records:
                    stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False))
                    stream.write("\n")
        (temp_path / METADATA_NAME).write_text(
            json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        for name in (*OUTPUT_NAMES, METADATA_NAME):
            os.replace(temp_path / name, destination / name)

    return metadata
