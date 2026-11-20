"""Reproducible, bounded telemetry transformation into graph-ready JSONL."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any, TextIO

from .normalization import SourceInfo, normalize_record
from .readers import ReadResult, iter_records


TRANSFORM_VERSION = "0.1.0"
OUTPUT_NAMES = (
    "entities.jsonl",
    "relationships.jsonl",
    "events.jsonl",
    "evidence.jsonl",
    "rejected.jsonl",
)
METADATA_NAME = "metadata.json"
COUNT_FIELDS = (
    "records_read",
    "records_accepted",
    "records_rejected",
    "invalid_records",
    "duplicates_skipped",
    "timestamps_unresolved",
    "entities",
    "relationships_seen",
    "relationships",
    "domain_relationships",
    "traceability_relationships",
    "evidence_records",
)


def _write_jsonl(stream: TextIO, record: dict[str, Any]) -> None:
    stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False))
    stream.write("\n")


def _register_once(index: sqlite3.Connection, kind: str, record_id: str) -> bool:
    cursor = index.execute(
        "INSERT OR IGNORE INTO seen_records (kind, record_id) VALUES (?, ?)",
        (kind, record_id),
    )
    return cursor.rowcount == 1


def _rejection(
    *,
    source: SourceInfo,
    source_file: str,
    locator: str,
    reason: str,
    source_record_id: str | None = None,
    raw_timestamp: Any = None,
    recoverable: bool = False,
) -> dict[str, Any]:
    rejection = {
        "source_dataset_id": source.dataset_id,
        "source_system": source.source_system,
        "source_file": source_file,
        "record_locator": locator,
        "source_record_id": source_record_id,
        "reason": reason,
        "recoverable": recoverable,
    }
    if raw_timestamp is not None:
        rejection["raw_timestamp"] = raw_timestamp
    return rejection


def run_pipeline(
    input_path: str | Path,
    output_dir: str | Path,
    *,
    dataset_id: str,
    source_system: str,
    source_version: str = "unknown",
    source_url: str | None = None,
    license_name: str | None = None,
    evidence_status: str = "observed",
    is_synthetic: bool = False,
    input_format: str | None = None,
    max_records: int | None = None,
) -> dict[str, Any]:
    """Transform one local CSV, JSON, or JSONL source into graph-ready records.

    The source is never downloaded or modified. Outputs are replaced only after
    a successful complete run; temporary ID indexes and partial outputs are removed.
    """
    source_path = Path(input_path)
    destination = Path(output_dir)
    if not source_path.is_file():
        raise FileNotFoundError(f"input file does not exist: {source_path}")
    if max_records is not None and max_records < 1:
        raise ValueError("max_records must be a positive integer")
    if evidence_status == "synthetic":
        is_synthetic = True
        evidence_status = "observed"
    if evidence_status not in {"observed", "derived", "unconfirmed"}:
        raise ValueError("evidence_status must be observed, derived, or unconfirmed")

    destination.mkdir(parents=True, exist_ok=True)
    source = SourceInfo(
        dataset_id=dataset_id,
        source_system=source_system,
        version=source_version,
        source_url=source_url,
        license=license_name,
        evidence_status=evidence_status,
        is_synthetic=is_synthetic,
    )
    started_at = datetime.now(timezone.utc)
    counters: Counter[str] = Counter(dict.fromkeys(COUNT_FIELDS, 0))
    warning_counts: Counter[str] = Counter()

    with tempfile.TemporaryDirectory(prefix="trustrail-pipeline-", dir=destination) as temp_dir:
        temp_path = Path(temp_dir)
        staged = {name: temp_path / name for name in OUTPUT_NAMES}
        with closing(sqlite3.connect(temp_path / "ids.sqlite3")) as index, index:
            index.execute(
                "CREATE TABLE seen_records (kind TEXT NOT NULL, record_id TEXT NOT NULL, "
                "PRIMARY KEY (kind, record_id))"
            )
            with (
                staged["events.jsonl"].open("w", encoding="utf-8", newline="\n") as events_out,
                staged["entities.jsonl"].open("w", encoding="utf-8", newline="\n") as entities_out,
                staged["relationships.jsonl"].open("w", encoding="utf-8", newline="\n") as relationships_out,
                staged["evidence.jsonl"].open("w", encoding="utf-8", newline="\n") as evidence_out,
                staged["rejected.jsonl"].open("w", encoding="utf-8", newline="\n") as rejected_out,
            ):
                results = iter_records(source_path, input_format)
                if max_records is not None:
                    results = islice(results, max_records)
                for result in results:
                    counters["records_read"] += 1
                    if result.error:
                        counters["records_rejected"] += 1
                        _write_jsonl(
                            rejected_out,
                            _rejection(
                                source=source,
                                source_file=source_path.name,
                                locator=result.locator,
                                reason=result.error,
                            ),
                        )
                        continue

                    if result.record is None:
                        counters["records_rejected"] += 1
                        _write_jsonl(
                            rejected_out,
                            _rejection(
                                source=source,
                                source_file=source_path.name,
                                locator=result.locator,
                                reason="reader returned neither a record nor a parsing error",
                            ),
                        )
                        continue
                    source_record_id = _source_record_id(result, source_path.name)
                    try:
                        normalized = normalize_record(
                            result.record,
                            source=source,
                            source_record_id=source_record_id,
                            ingested_at=started_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
                        )
                    except (TypeError, ValueError) as error:
                        counters["records_rejected"] += 1
                        _write_jsonl(
                            rejected_out,
                            _rejection(
                                source=source,
                                source_file=source_path.name,
                                locator=result.locator,
                                source_record_id=source_record_id,
                                reason=str(error),
                            ),
                        )
                        continue

                    event = normalized.event
                    counters["records_accepted"] += 1
                    if _register_once(index, "event", event["event_id"]):
                        _write_jsonl(events_out, event)
                    else:
                        counters["duplicates_skipped"] += 1
                    for warning in normalized.warnings:
                        warning_counts[warning] += 1
                    if event["event_time"] is None:
                        counters["invalid_records"] += 1
                        counters["timestamps_unresolved"] += 1
                        _write_jsonl(
                            rejected_out,
                            _rejection(
                                source=source,
                                source_file=source_path.name,
                                locator=result.locator,
                                source_record_id=source_record_id,
                                reason=f"event timestamp requires validation: {event['timestamp_semantics']}",
                                raw_timestamp=event["event_time_original"],
                                recoverable=True,
                            ),
                        )
                    if normalized.relationship:
                        counters["relationships_seen"] += 1
                    if _register_once(index, "evidence", normalized.evidence["evidence_id"]):
                        _write_jsonl(evidence_out, normalized.evidence)
                        counters["evidence_records"] += 1
                    for entity in normalized.entities:
                        if _register_once(index, "entity", entity["id"]):
                            _write_jsonl(entities_out, entity)
                            counters["entities"] += 1
                    relationships = (
                        *((normalized.relationship,) if normalized.relationship else ()),
                        *normalized.trace_relationships,
                    )
                    for relationship in relationships:
                        relationship_id = relationship["relationship_id"]
                        if _register_once(index, "relationship", relationship_id):
                            _write_jsonl(relationships_out, relationship)
                            counters["relationships"] += 1
                            if relationship["relationship_type"] in {"SUPPORTED_BY", "OBSERVED_ON"}:
                                counters["traceability_relationships"] += 1
                            else:
                                counters["domain_relationships"] += 1

        finished_at = datetime.now(timezone.utc)
        metadata: dict[str, Any] = {
            "dataset_id": dataset_id,
            "source_system": source_system,
            "source_version": source_version,
            "source_url": source_url,
            "license": license_name,
            "source_file": source_path.name,
            "source_size_bytes": source_path.stat().st_size,
            "source_format": input_format or source_path.suffix.lower().lstrip("."),
            "evidence_status": evidence_status,
            "is_synthetic": is_synthetic,
            "transform_version": TRANSFORM_VERSION,
            "started_at": started_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "finished_at": finished_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            "max_records": max_records,
            "counts": dict(sorted(counters.items())),
            "warning_counts": dict(sorted(warning_counts.items())),
            "outputs": [*OUTPUT_NAMES, METADATA_NAME],
        }
        staged_metadata = temp_path / METADATA_NAME
        staged_metadata.write_text(
            json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        for name in OUTPUT_NAMES:
            os.replace(staged[name], destination / name)
        os.replace(staged_metadata, destination / METADATA_NAME)

    return metadata


def _source_record_id(result: ReadResult, filename: str) -> str:
    if result.record is not None:
        for key in ("source_record_id", "RecordID", "record_id", "event_id", "id", "_id"):
            value = result.record.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
    return f"{filename}#{result.locator}"
