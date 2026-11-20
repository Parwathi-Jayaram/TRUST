"""Data loading for Member 4 ML layer.

Consumes:
  - Member 3 normalized events.jsonl (synthetic TRUSTRAIL dataset)
  - UNSW-NB15 training/testing CSVs (when available and approved)

All loaders preserve event identifiers and synthetic provenance flags.
"""

from __future__ import annotations

import json
import csv
from pathlib import Path
from typing import Any
import pandas as pd


def load_member3_events(events_path: str | Path) -> pd.DataFrame:
    """Load Member 3 normalized events.jsonl into a DataFrame.

    Expected fields (per ingestion_contract.md / normalized_data_dictionary.md):
      event_id, event_type, event_time, event_time_original,
      timestamp_semantics, severity, description, evidence_id,
      evidence_status, ingested_at, is_synthetic, source_record_id,
      source_system, plus optional nested 'attributes' dict.
    """
    events_path = Path(events_path)
    if not events_path.is_file():
        raise FileNotFoundError(f"events file not found: {events_path}")

    records: list[dict[str, Any]] = []
    with events_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no}: {exc}") from exc
            records.append(record)

    df = pd.DataFrame(records)

    # Flatten nested 'attributes' dict into top-level columns if present.
    if "attributes" in df.columns:
        attrs = df["attributes"].apply(lambda x: x if isinstance(x, dict) else {})
        attrs_df = pd.json_normalize(attrs)
        attrs_df.columns = [f"attr_{c}" for c in attrs_df.columns]
        df = df.drop(columns=["attributes"]).reset_index(drop=True)
        df = pd.concat([df, attrs_df.reset_index(drop=True)], axis=1)

    # Ensure required columns exist.
    required = ["event_id", "event_type", "is_synthetic"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in events.jsonl: {missing}")

    return df


def load_unsw_nb15(
    training_path: str | Path,
    testing_path: str | Path,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load UNSW-NB15 training and testing CSV partitions.

    Returns (train_df, test_df). Columns are inspected at load time;
    no assumptions are made about specific column names beyond what
    the file actually contains.
    """
    training_path = Path(training_path)
    testing_path = Path(testing_path)

    if not training_path.is_file():
        raise FileNotFoundError(f"UNSW-NB15 training file not found: {training_path}")
    if not testing_path.is_file():
        raise FileNotFoundError(f"UNSW-NB15 testing file not found: {testing_path}")

    train_df = pd.read_csv(training_path)
    test_df = pd.read_csv(testing_path)

    return train_df, test_df


def load_synthetic_csvs(
    entities_path: str | Path,
    relationships_path: str | Path,
    events_path: str | Path,
    evidence_path: str | Path,
) -> dict[str, pd.DataFrame]:
    """Load the synthetic TRUSTRAIL split-CSV dataset (Dataset A).

    Returns a dict with keys: entities, relationships, events, evidence.
    """
    paths = {
        "entities": Path(entities_path),
        "relationships": Path(relationships_path),
        "events": Path(events_path),
        "evidence": Path(evidence_path),
    }
    frames: dict[str, pd.DataFrame] = {}
    for name, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"Synthetic {name} file not found: {path}")
        frames[name] = pd.read_csv(path)
    return frames


def validate_event_schema(df: pd.DataFrame, source_name: str) -> list[str]:
    """Return a list of schema warnings for an events DataFrame.

    Checks for identifier columns, leakage-prone fields, missing values,
    and duplicates. Does not modify the DataFrame.
    """
    warnings: list[str] = []

    id_candidates = [c for c in df.columns if c.lower() in {"id", "event_id", "source_record_id"}]
    if id_candidates:
        warnings.append(f"[{source_name}] Identifier columns present: {id_candidates}")

    leakage_candidates = [c for c in df.columns if c.lower() in {"attack_cat", "label"}]
    if leakage_candidates:
        warnings.append(f"[{source_name}] Potential target/leakage columns present: {leakage_candidates}")

    missing = df.isnull().sum()
    missing_cols = missing[missing > 0]
    if not missing_cols.empty:
        warnings.append(f"[{source_name}] Missing values: {missing_cols.to_dict()}")

    dupes = df.duplicated().sum()
    if dupes > 0:
        warnings.append(f"[{source_name}] Duplicate rows: {dupes}")

    return warnings


def summarize_dataframe(df: pd.DataFrame, name: str) -> dict[str, Any]:
    """Produce a concise summary dict for a DataFrame."""
    return {
        "name": name,
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "column_names": list(df.columns),
        "numeric_columns": list(df.select_dtypes(include="number").columns),
        "categorical_columns": list(df.select_dtypes(exclude="number").columns),
        "missing_values": df.isnull().sum().to_dict(),
        "duplicate_rows": int(df.duplicated().sum()),
        "memory_mb": round(df.memory_usage(deep=True).sum() / (1024 * 1024), 3),
    }
