"""Phase 1 — Dataset exploration and audit for Member 4.

Loads Member 3 synthetic events.jsonl and (if present) UNSW-NB15 CSVs,
inspects dimensions, columns, types, missing values, duplicates, label
distributions, and leakage fields, then writes a dataset audit report.

Run from the TRUST repo root:
  $env:PYTHONPATH = "src;member4_ml/src"
  python member4_ml/notebooks/01_dataset_exploration.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

# Allow running both as a script and as a module.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "member4_ml" / "src"))

from data_loader import (
    load_member3_events,
    load_unsw_nb15,
    load_synthetic_csvs,
    validate_event_schema,
    summarize_dataframe,
)

TRUST_ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_EVENTS = TRUST_ROOT / "data" / "demo-run" / "processed" / "events.jsonl"
SYNTHETIC_DIR = TRUST_ROOT / "data" / "demo-run" / "processed"
UNSW_DIR = TRUST_ROOT / "member4_ml" / "datasets" / "unsw_nb15"
UNSW_TRAIN = UNSW_DIR / "UNSW_NB15_training-set.csv"
UNSW_TEST = UNSW_DIR / "UNSW_NB15_testing-set.csv"
REPORT_DIR = TRUST_ROOT / "member4_ml" / "reports"


def explore_member3_synthetic() -> dict:
    """Explore the Member 3 synthetic events.jsonl (Dataset A integration fixture)."""
    print("=" * 70)
    print("DATASET A — Synthetic TRUSTRAIL events (Member 3 events.jsonl)")
    print("=" * 70)

    df = load_member3_events(SYNTHETIC_EVENTS)
    summary = summarize_dataframe(df, "synthetic_events.jsonl")
    print(summary)

    warnings = validate_event_schema(df, "synthetic_events.jsonl")
    print("\nSchema warnings:")
    for w in warnings:
        print("  -", w)
    if not warnings:
        print("  None")

    print("\nColumn data types:")
    print(df.dtypes)

    print("\nFirst 3 rows (transposed):")
    print(df.head(3).T.to_string())

    if "event_type" in df.columns:
        print("\nevent_type distribution:")
        print(df["event_type"].value_counts(dropna=False))

    if "is_synthetic" in df.columns:
        print("\nis_synthetic distribution:")
        print(df["is_synthetic"].value_counts(dropna=False))

    if "evidence_status" in df.columns:
        print("\nevidence_status distribution:")
        print(df["evidence_status"].value_counts(dropna=False))

    if "severity" in df.columns:
        print("\nseverity distribution:")
        print(df["severity"].value_counts(dropna=False))

    # Network-flow attribute columns (flattened by loader).
    attr_cols = [c for c in df.columns if c.startswith("attr_")]
    if attr_cols:
        print("\nNetwork-flow attribute columns present:", attr_cols)
        for c in attr_cols:
            print(f"  {c}: {df[c].dropna().describe().to_dict()}")

    return {"summary": summary, "warnings": warnings, "df": df}


def explore_unsw_nb15() -> dict | None:
    """Explore UNSW-NB15 training/testing CSVs (Dataset B) if present."""
    if not UNSW_TRAIN.is_file() or not UNSW_TEST.is_file():
        print("\n" + "=" * 70)
        print("DATASET B — UNSW-NB15: NOT AVAILABLE (download blocked)")
        print("=" * 70)
        print("Expected files:")
        print(f"  {UNSW_TRAIN}")
        print(f"  {UNSW_TEST}")
        print("SharePoint source requires authentication; Member 1 approval needed.")
        print("Proceeding with synthetic Dataset A only for Phase 1.")
        return None

    print("=" * 70)
    print("DATASET B — UNSW-NB15 (train / test partitions)")
    print("=" * 70)

    train_df, test_df = load_unsw_nb15(UNSW_TRAIN, UNSW_TEST)

    train_summary = summarize_dataframe(train_df, "UNSW_NB15_training-set.csv")
    test_summary = summarize_dataframe(test_df, "UNSW_NB15_testing-set.csv")

    print("\nTRAINING SET:")
    print(train_summary)
    print("\nColumn data types (training):")
    print(train_df.dtypes)

    print("\nTESTING SET:")
    print(test_summary)
    print("\nColumn data types (testing):")
    print(test_df.dtypes)

    # Schema comparison.
    train_cols = set(train_df.columns)
    test_cols = set(test_df.columns)
    print("\nSchema comparison:")
    print(f"  Columns only in training: {sorted(train_cols - test_cols)}")
    print(f"  Columns only in testing:  {sorted(test_cols - train_cols)}")
    print(f"  Common columns:           {len(train_cols & test_cols)}")

    # Leakage check.
    warnings = validate_event_schema(train_df, "UNSW-NB15 train")
    warnings += validate_event_schema(test_df, "UNSW-NB15 test")
    print("\nSchema warnings:")
    for w in warnings:
        print("  -", w)
    if not warnings:
        print("  None")

    # Label distributions.
    for label_col in ("label", "attack_cat"):
        if label_col in train_df.columns:
            print(f"\nTraining {label_col} distribution:")
            print(train_df[label_col].value_counts(dropna=False))
        if label_col in test_df.columns:
            print(f"\nTesting {label_col} distribution:")
            print(test_df[label_col].value_counts(dropna=False))

    return {
        "train_summary": train_summary,
        "test_summary": test_summary,
        "train_df": train_df,
        "test_df": test_df,
    }


def write_audit_report(
    synth_result: dict,
    unsw_result: dict | None,
) -> Path:
    """Write the dataset audit report to reports/dataset_audit.md."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / "dataset_audit.md"

    lines: list[str] = []
    lines.append("# TRUSTRAIL AI — Member 4 Dataset Audit Report (Phase 1)")
    lines.append("")
    lines.append("## 1. Synthetic TRUSTRAIL Dataset (Dataset A) — Member 3 events.jsonl")
    lines.append("")
    s = synth_result["summary"]
    lines.append(f"- Source: `{SYNTHETIC_EVENTS}`")
    lines.append(f"- Rows: {s['rows']}")
    lines.append(f"- Columns: {s['columns']}")
    lines.append(f"- Numeric columns: {s['numeric_columns']}")
    lines.append(f"- Categorical columns: {s['categorical_columns']}")
    lines.append(f"- Missing values: {s['missing_values']}")
    lines.append(f"- Duplicate rows: {s['duplicate_rows']}")
    lines.append(f"- Memory usage: {s['memory_mb']} MB")
    lines.append("")
    lines.append("### Schema warnings")
    for w in synth_result["warnings"]:
        lines.append(f"- {w}")
    if not synth_result["warnings"]:
        lines.append("- None")
    lines.append("")
    lines.append("### Column data types")
    df = synth_result["df"]
    for col, dtype in df.dtypes.items():
        lines.append(f"- {col}: {dtype}")
    lines.append("")
    lines.append("### Usage in Member 4")
    lines.append("- Used for integration testing, I/O format validation, and pipeline smoke tests.")
    lines.append("- All records carry `is_synthetic: true`; never presented as real-world performance.")
    lines.append("- Not used to train production models or claim real detection accuracy.")
    lines.append("")

    lines.append("## 2. UNSW-NB15 Dataset (Dataset B)")
    lines.append("")
    if unsw_result is None:
        lines.append("- Status: **Not available** — download blocked.")
        lines.append("- Official source: https://research.unsw.edu.au/projects/unsw-nb15-dataset")
        lines.append("- SharePoint download requires authentication; Member 1 approval needed.")
        lines.append("- Expected files: `UNSW_NB15_training-set.csv` (175,341 rows), `UNSW_NB15_testing-set.csv` (82,332 rows).")
        lines.append("- Nine attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms.")
        lines.append("- Will be used for supervised binary + multiclass training once downloaded and approved.")
        lines.append("- Academic use only; commercial use requires author agreement. Citation required.")
    else:
        ts = unsw_result["train_summary"]
        xs = unsw_result["test_summary"]
        lines.append(f"- Training rows: {ts['rows']}, columns: {ts['columns']}")
        lines.append(f"- Testing rows: {xs['rows']}, columns: {xs['columns']}")
        lines.append(f"- Training numeric columns: {ts['numeric_columns']}")
        lines.append(f"- Testing numeric columns: {xs['numeric_columns']}")
        lines.append(f"- Schema match: {len(set(ts['column_names']) & set(xs['column_names']))} common columns")
        lines.append("")
        lines.append("### Schema warnings")
        for w in (unsw_result.get("warnings") or []):
            lines.append(f"- {w}")
    lines.append("")
    lines.append("## 3. Leakage Prevention Checklist")
    lines.append("- Binary classification target: `label` (never `attack_cat` as input).")
    lines.append("- Multiclass classification target: `attack_cat` (never `label` as input).")
    lines.append("- Identifier columns (`id`, `event_id`, `source_record_id`) excluded from model features.")
    lines.append("- Preprocessing fitted only on training data; applied to validation/test.")
    lines.append("- No resampling applied to the test set.")
    lines.append("")
    lines.append("## 4. Recommendations")
    lines.append("- Proceed with Phase 2 preprocessing using the Member 3 synthetic events.jsonl schema.")
    lines.append("- Download UNSW-NB15 only after Member 1 confirms academic-use approval.")
    lines.append("- Keep synthetic test outcomes separate from public-dataset evaluation results.")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nAudit report written to: {report_path}")
    return report_path


def main() -> None:
    print("TRUSTRAIL AI — Member 4 Phase 1: Dataset Exploration & Audit")
    print()

    synth_result = explore_member3_synthetic()
    unsw_result = explore_unsw_nb15()
    write_audit_report(synth_result, unsw_result)

    print("\nPhase 1 exploration complete.")


if __name__ == "__main__":
    main()
