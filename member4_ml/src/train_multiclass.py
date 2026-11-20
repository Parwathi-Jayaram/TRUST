"""Phase 4 — Multiclass Attack Classification (Member 4).

Trains and compares baseline models for classifying suspicious traffic
into UNSW-NB15 attack categories. Evaluates once on the held-out test
partition with per-class precision/recall and confusion matrix.

Run from the TRUST repo root once UNSW-NB15 CSVs are available:
  $env:PYTHONPATH = "src;member4_ml/src"
  python member4_ml/src/train_multiclass.py \
    --train <path-to-UNSW_NB15_training-set.csv> \
    --test <path-to-UNSW_NB15_testing-set.csv> \
    --model-dir member4_ml/models \
    --report-dir member4_ml/reports

Without --train/--test, runs a smoke check on synthetic Member 3 data
(integration smoke test only; not real performance).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split

from preprocessing import (
    build_preprocessor,
    fit_preprocessor,
    transform_preprocessor,
    get_feature_names,
    save_preprocessor,
    separate_X_y,
    identify_feature_columns,
    LEAKAGE_COLUMNS_MULTICLASS,
    IDENTIFIER_COLUMNS,
    TARGET_MULTICLASS,
)


# Expected UNSW-NB15 attack categories (from dataset documentation).
EXPECTED_ATTACK_CATEGORIES = [
    "Fuzzers",
    "Analysis",
    "Backdoors",
    "DoS",
    "Exploits",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
]


def get_multiclass_models(random_state: int = 42) -> dict[str, Any]:
    """Return candidate multiclass classification models.

    - DummyClassifier (stratified): baseline to beat.
    - LogisticRegression: multinomial, simple linear baseline.
    - RandomForestClassifier: tree-based, native multiclass, provides
      feature importances, fast on ~175k records.
    """
    return {
        "dummy_stratified": DummyClassifier(strategy="stratified", random_state=random_state),
        "logistic_regression": LogisticRegression(
            max_iter=1000,
            random_state=random_state,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1,
        ),
    }


def train_and_compare(
    X_train: np.ndarray,
    y_train: pd.Series,
    X_val: np.ndarray,
    y_val: pd.Series,
    models: dict[str, Any],
    labels: list[str] | None = None,
    random_state: int = 42,
) -> dict[str, dict[str, Any]]:
    """Train each model on train, evaluate on validation, return results."""
    results: dict[str, dict[str, Any]] = {}

    for name, model in models.items():
        model.fit(X_train, y_train)

        y_val_pred = model.predict(X_val)
        val_metrics = _compute_multiclass_metrics(y_val, y_val_pred, labels=labels)

        results[name] = {
            "model": model,
            "validation_metrics": val_metrics,
        }

        print(f"\n{name}:")
        for key in ("accuracy", "macro_f1", "weighted_f1"):
            print(f"  {key}: {val_metrics[key]:.4f}")

    return results


def _compute_multiclass_metrics(
    y_true: pd.Series,
    y_pred: np.ndarray,
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """Compute multiclass classification metrics."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    if labels is None:
        labels = sorted(np.unique(np.concatenate([y_true, y_pred])).tolist())

    metrics: dict[str, Any] = {}
    metrics["accuracy"] = float(accuracy_score(y_true, y_pred))
    metrics["macro_f1"] = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    metrics["weighted_f1"] = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    metrics["macro_precision"] = float(
        precision_score(y_true, y_pred, average="macro", zero_division=0)
    )
    metrics["macro_recall"] = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    metrics["confusion_matrix"] = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    metrics["confusion_matrix_labels"] = [str(l) for l in labels]

    # Per-class precision/recall/f1/support.
    per_class: dict[str, dict[str, float]] = {}
    precisions, recalls, f1s, supports = _per_class_scores(y_true, y_pred, labels=labels)
    for i, label in enumerate(labels):
        per_class[str(label)] = {
            "precision": float(precisions[i]),
            "recall": float(recalls[i]),
            "f1": float(f1s[i]),
            "support": int(supports[i]),
        }
    metrics["per_class"] = per_class

    try:
        metrics["classification_report"] = classification_report(
            y_true, y_pred, labels=labels, zero_division=0, output_dict=True
        )
    except Exception:
        metrics["classification_report"] = None

    return metrics


def _per_class_scores(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: list[str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Compute per-class precision, recall, f1, support."""
    from sklearn.metrics import precision_recall_f1_score as _prfs

    return _prfs(y_true, y_pred, labels=labels, zero_division=0, average=None)


def select_best_model(
    results: dict[str, dict[str, Any]],
    metric: str = "macro_f1",
) -> str:
    """Select the best model by validation metric (default macro_f1).

    macro_f1 is preferred over accuracy for multiclass because it
    reveals poor performance on minority attack categories.
    """
    best_name = None
    best_value = -1.0
    for name, result in results.items():
        value = result["validation_metrics"].get(metric)
        if value is None:
            continue
        if value > best_value:
            best_value = value
            best_name = name
    if best_name is None:
        raise ValueError("No model could be selected; all validation metrics are None.")
    return best_name


def evaluate_on_test(
    model: Any,
    X_test: np.ndarray,
    y_test: pd.Series,
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate the selected model once on the held-out test partition."""
    y_test_pred = model.predict(X_test)
    test_metrics = _compute_multiclass_metrics(y_test, y_test_pred, labels=labels)
    return test_metrics


def save_model_artifacts(
    model: Any,
    preprocessor: Any,
    feature_names: list[str],
    model_path: str | Path,
    preprocessor_path: str | Path,
    metadata_path: str | Path,
    model_name: str,
    test_metrics: dict[str, Any],
    labels: list[str] | None = None,
) -> None:
    """Save fitted model, preprocessor, and metadata."""
    model_path = Path(model_path)
    preprocessor_path = Path(preprocessor_path)
    metadata_path = Path(metadata_path)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    preprocessor_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, model_path)
    joblib.dump(preprocessor, preprocessor_path)

    metadata = {
        "model_name": model_name,
        "model_file": model_path.name,
        "preprocessor_file": preprocessor_path.name,
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "test_metrics": test_metrics,
        "task": "multiclass_attack_classification",
        "target": TARGET_MULTICLASS,
        "labels": labels,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"\nSaved model: {model_path}")
    print(f"Saved preprocessor: {preprocessor_path}")
    print(f"Saved metadata: {metadata_path}")


def load_synthetic_multiclass_demo(events_path: str | Path) -> dict[str, Any]:
    """Build a synthetic multiclass demo from Member 3 events.

    Pseudo-label based on event_type for pipeline smoke test only:
    network_flow -> reconnaissance, process -> exploits, others -> normal.
    NOT real-world performance.
    """
    from data_loader import load_member3_events

    df = load_member3_events(events_path)
    df = df.copy()

    type_to_category = {
        "network_flow": "Reconnaissance",
        "process": "Exploits",
        "authentication": "Normal",
        "dependency_observation": "Normal",
        "vulnerability_observation": "Normal",
        "incident_association": "Normal",
    }
    df[TARGET_MULTICLASS] = df["event_type"].map(type_to_category).fillna("Normal")

    feature_columns = identify_feature_columns(df, TARGET_MULTICLASS, task_type="multiclass")

    X = df[feature_columns]
    y = df[TARGET_MULTICLASS]

    preprocessor = build_preprocessor(df, TARGET_MULTICLASS, task_type="multiclass")
    preprocessor = fit_preprocessor(preprocessor, X)
    X_t = transform_preprocessor(preprocessor, X)
    feature_names = get_feature_names(preprocessor)

    models = get_multiclass_models()
    for name, model in models.items():
        model.fit(X_t, y)

    labels = sorted(y.unique().tolist())

    return {
        "models": models,
        "preprocessor": preprocessor,
        "feature_names": feature_names,
        "n_samples": len(df),
        "label_distribution": y.value_counts().to_dict(),
        "labels": labels,
        "is_smoke_test": True,
    }


def run_multiclass_pipeline(
    train_path: str | Path | None,
    test_path: str | Path | None,
    model_dir: str | Path,
    report_dir: str | Path,
    random_state: int = 42,
    validation_size: float = 0.2,
) -> dict[str, Any]:
    """Run the full multiclass classification pipeline."""
    model_dir = Path(model_dir)
    report_dir = Path(report_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    if train_path is None or test_path is None:
        print("=== MULTICLASS CLASSIFICATION — SYNTHETIC SMOKE TEST (not real performance) ===")
        demo = load_synthetic_multiclass_demo(
            Path(__file__).resolve().parents[2]
            / "data"
            / "demo-run"
            / "processed"
            / "events.jsonl"
        )
        print(f"\nSmoke test samples: {demo['n_samples']}")
        print(f"Label distribution: {demo['label_distribution']}")
        print(f"Labels: {demo['labels']}")
        print(f"Feature count: {len(demo['feature_names'])}")
        print("\nModels trained on synthetic data (pipeline smoke test only).")
        print("UNSW-NB15 required for real training/evaluation.")
        return {
            "status": "smoke_test",
            "models": demo["models"],
            "preprocessor": demo["preprocessor"],
            "feature_names": demo["feature_names"],
            "labels": demo["labels"],
        }

    from data_loader import load_unsw_nb15

    print("=== MULTICLASS CLASSIFICATION — UNSW-NB15 (real training) ===")
    train_df, test_df = load_unsw_nb15(train_path, test_path)

    print(f"\nTraining rows: {len(train_df)}, Testing rows: {len(test_df)}")
    if TARGET_MULTICLASS not in train_df.columns:
        raise ValueError(
            f"Target column {TARGET_MULTICLASS!r} not found in training data. "
            f"Columns: {list(train_df.columns)}"
        )

    feature_columns = identify_feature_columns(train_df, TARGET_MULTICLASS, task_type="multiclass")
    print(f"Feature columns ({len(feature_columns)}): {feature_columns}")

    preprocessor = build_preprocessor(train_df, TARGET_MULTICLASS, task_type="multiclass")
    preprocessor = fit_preprocessor(preprocessor, train_df[feature_columns])

    X_train_all = transform_preprocessor(preprocessor, train_df[feature_columns])
    y_train_all = train_df[TARGET_MULTICLASS]
    feature_names = get_feature_names(preprocessor)

    X_test = transform_preprocessor(preprocessor, test_df[feature_columns])
    y_test = test_df[TARGET_MULTICLASS]

    labels = sorted(y_train_all.unique().tolist())
    print(f"Detected attack categories ({len(labels)}): {labels}")

    X_train, X_val, y_train, y_val = train_test_split(
        X_train_all,
        y_train_all,
        test_size=validation_size,
        random_state=random_state,
        stratify=y_train_all,
    )

    print(f"\nTrain/validation split: {len(X_train)} train / {len(X_val)} validation")

    models = get_multiclass_models(random_state=random_state)
    results = train_and_compare(X_train, y_train, X_val, y_val, models, labels=labels, random_state=random_state)

    best_name = select_best_model(results, metric="macro_f1")
    best_model = results[best_name]["model"]
    print(f"\nBest model (validation macro F1): {best_name}")

    test_metrics = evaluate_on_test(best_model, X_test, y_test, labels=labels)
    print("\n=== Held-out test set evaluation (single pass) ===")
    for key in ("accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1"):
        print(f"  {key}: {test_metrics[key]:.4f}")

    print("\nPer-class metrics (test set):")
    for label, m in test_metrics["per_class"].items():
        print(
            f"  {label}: precision={m['precision']:.3f} "
            f"recall={m['recall']:.3f} f1={m['f1']:.3f} support={m['support']}"
        )

    model_path = model_dir / "multiclass_model.joblib"
    preprocessor_path = model_dir / "multiclass_preprocessor.joblib"
    metadata_path = report_dir / "multiclass_model_metadata.json"
    save_model_artifacts(
        model=best_model,
        preprocessor=preprocessor,
        feature_names=feature_names,
        model_path=model_path,
        preprocessor_path=preprocessor_path,
        metadata_path=metadata_path,
        model_name=best_name,
        test_metrics=test_metrics,
        labels=labels,
    )

    comparison_lines = ["# Multiclass Model Comparison Report\n"]
    comparison_lines.append(
        "| Model | Accuracy | Macro Precision | Macro Recall | Macro F1 | Weighted F1 |"
    )
    comparison_lines.append(
        "|-------|----------|-----------------|--------------|----------|-------------|"
    )
    for name, result in results.items():
        m = result["validation_metrics"]
        comparison_lines.append(
            f"| {name} | {m['accuracy']:.4f} | {m['macro_precision']:.4f} | "
            f"{m['macro_recall']:.4f} | {m['macro_f1']:.4f} | {m['weighted_f1']:.4f} |"
        )
    comparison_path = report_dir / "multiclass_model_comparison.md"
    comparison_path.write_text("\n".join(comparison_lines), encoding="utf-8")
    print(f"\nSaved model comparison: {comparison_path}")

    eval_lines = [
        "# Multiclass Attack Classification — Evaluation Report\n",
        f"## Selected model: {best_name}\n",
        "## Held-out test set metrics (single evaluation pass)\n",
    ]
    for key in ("accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1"):
        eval_lines.append(f"- {key}: {test_metrics[key]:.4f}")
    eval_lines.append("\n## Per-class metrics\n")
    for label, m in test_metrics["per_class"].items():
        eval_lines.append(
            f"- {label}: precision={m['precision']:.3f}, "
            f"recall={m['recall']:.3f}, f1={m['f1']:.3f}, support={m['support']}"
        )
    cm = test_metrics["confusion_matrix"]
    cm_labels = test_metrics["confusion_matrix_labels"]
    eval_lines.append("\n## Confusion Matrix\n")
    eval_lines.append("| | " + " | ".join(cm_labels) + " |")
    eval_lines.append("|---|" + "---|" * len(cm_labels))
    for i, row_label in enumerate(cm_labels):
        eval_lines.append(
            f"| {row_label} | " + " | ".join(str(v) for v in cm[i]) + " |"
        )
    eval_path = report_dir / "multiclass_evaluation_report.md"
    eval_path.write_text("\n".join(eval_lines), encoding="utf-8")
    print(f"Saved evaluation report: {eval_path}")

    return {
        "status": "complete",
        "best_model": best_name,
        "best_model_object": best_model,
        "preprocessor": preprocessor,
        "feature_names": feature_names,
        "test_metrics": test_metrics,
        "labels": labels,
        "validation_results": {name: r["validation_metrics"] for name, r in results.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 4: Multiclass Attack Classification training and evaluation."
    )
    parser.add_argument("--train", type=str, default=None, help="Path to UNSW-NB15 training CSV")
    parser.add_argument("--test", type=str, default=None, help="Path to UNSW-NB15 testing CSV")
    parser.add_argument(
        "--model-dir",
        type=str,
        default="member4_ml/models",
        help="Directory to save model artifacts",
    )
    parser.add_argument(
        "--report-dir",
        type=str,
        default="member4_ml/reports",
        help="Directory to save reports",
    )
    parser.add_argument(
        "--validation-size",
        type=float,
        default=0.2,
        help="Fraction of training data to use as validation",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    run_multiclass_pipeline(
        train_path=args.train,
        test_path=args.test,
        model_dir=args.model_dir,
        report_dir=args.report_dir,
        random_state=args.random_state,
        validation_size=args.validation_size,
    )


if __name__ == "__main__":
    main()
