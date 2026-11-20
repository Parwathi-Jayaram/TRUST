"""Streaming readers for supported local telemetry formats."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


MAX_JSON_DOCUMENT_BYTES = 16 * 1024 * 1024


def _reject_non_finite_constant(token: str) -> None:
    raise ValueError(f"non-standard non-finite JSON value: {token}")


@dataclass(frozen=True)
class ReadResult:
    locator: str
    record: dict[str, Any] | None = None
    error: str | None = None


def detect_format(path: Path, requested: str | None = None) -> str:
    if requested:
        value = requested.lower().lstrip(".")
    else:
        suffix = path.suffix.lower()
        value = {
            ".csv": "csv",
            ".json": "json",
            ".jsonl": "jsonl",
            ".ndjson": "jsonl",
        }.get(suffix, "")
    if value not in {"csv", "json", "jsonl"}:
        raise ValueError(f"Unsupported input format for {path.name!r}: {value or 'unknown'}")
    return value


def iter_records(path: Path, input_format: str | None = None) -> Iterator[ReadResult]:
    """Yield records without loading CSV or JSONL input into memory."""
    data_format = detect_format(path, input_format)

    if data_format == "csv":
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if (
                not reader.fieldnames
                or any(not name or not name.strip() for name in reader.fieldnames)
                or len({name.strip().casefold() for name in reader.fieldnames}) != len(reader.fieldnames)
            ):
                raise ValueError(f"CSV file has no usable header: {path}")
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    yield ReadResult(f"line:{row_number}", error="row has more values than the header")
                    continue
                yield ReadResult(f"line:{row_number}", record=dict(row))
        return

    if data_format == "jsonl":
        with path.open("r", encoding="utf-8-sig") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line, parse_constant=_reject_non_finite_constant)
                except json.JSONDecodeError as error:
                    yield ReadResult(
                        f"line:{line_number}",
                        error=f"invalid JSON at column {error.colno}: {error.msg}",
                    )
                    continue
                except ValueError as error:
                    yield ReadResult(f"line:{line_number}", error=str(error))
                    continue
                if not isinstance(value, dict):
                    yield ReadResult(f"line:{line_number}", error="JSONL record must be an object")
                    continue
                yield ReadResult(f"line:{line_number}", record=value)
        return

    size = path.stat().st_size
    if size > MAX_JSON_DOCUMENT_BYTES:
        raise ValueError(
            f"JSON document is {size} bytes; the in-memory JSON limit is "
            f"{MAX_JSON_DOCUMENT_BYTES} bytes. Convert it to JSONL or use a smaller file."
        )
    with path.open("r", encoding="utf-8-sig") as stream:
        value = json.load(stream, parse_constant=_reject_non_finite_constant)
    if isinstance(value, dict):
        yield ReadResult("document:1", record=value)
    elif isinstance(value, list):
        for index, item in enumerate(value, start=1):
            if isinstance(item, dict):
                yield ReadResult(f"item:{index}", record=item)
            else:
                yield ReadResult(f"item:{index}", error="JSON array item must be an object")
    else:
        raise ValueError("JSON document must contain an object or an array of objects")
