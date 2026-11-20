"""Phase 3 — Binary Intrusion Detection (Member 4).

Trains and compares a small set of baseline models for classifying a
network event as Normal vs Attack. Evaluates once on the held-out test
partition and saves the fitted pipeline + model.

Run from the TRUST repo root once UNSW-NB15 CSVs are available:
  $env:PYTHONPATH = "src;member4_ml/src"
  python member4_ml/src/train_binary.py \
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
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split

sys_path_hint = None  # placeholder; data_loader imported via sys.path by caller

from preprocessing import (
    build_preprocessor,
    fit_preprocessor,
    transform_preprocessor,
    get_feature_names,
    save_preprocessor,
    separate_X_y,
    identify_feature_columns,
    LEAKAGE_COLUMNS_BINARY,
    IDENTIFIER_COLUMNS,
    TARGET_BINARY,
)


# ---------------------------------------------------------------------------
# Model registry: small, meaningful set compared fairly. No model inflation.
# ---------------------------------------------------------------------------

def get_binary_models(random_state: int = 42) -> dict[str, Any]:
    """Return the candidate binary classification models.

    - DummyClassifier (stratified): baseline to beat.
    - LogisticRegression: simple, interpretable linear baseline.
    - RandomForestClassifier: tree-based, provides feature importances,
      handles mixed types after encoding, fast on ~175k records.
    """
    return {
        "dummy_stratified": DummyClassifier(strategy="stratified", random_state=random_state),
        "logistic_regression": LogisticRegression(
            max_iter=1000, random_state=random_state, n_jobs=None
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
    random_state: int = 42,
) -> dict[str, dict[str, Any]]:
    """Train each model on train, evaluate on validation, return results.

    Returns a dict keyed by model name with fitted model and metrics.
    """
    results: dict[str, dict[str, Any]] = {}

    for name, model in models.items():
        model.fit(X_train, y_train)

        # Validation predictions.
        y_val_pred = model.predict(X_val)
        val_metrics = _compute_binary_metrics(y_val, y_val_pred, model, X_val)

        results[name] = {
            "model": model,
            "validation_metrics": val_metrics,
        }

        print(f"\n{name}:")
        for metric, value in val_metrics.items():
            if metric in ("confusion_matrix", "classification_report"):
                continue
            print(f"  {metric}: {value:.4f}")

    return results


def _compute_binary_metrics(
    y_true: pd.Series,
    y_pred: np.ndarray,
    model: Any,
    X: np.ndarray,
) -> dict[str, Any]:
    """Compute standard binary classification metrics."""
    metrics: dict[str, Any] = {}
    metrics["accuracy"] = float(accuracy_score(y_true, y_pred))
    metrics["precision"] = float(
        precision_score(y_true, y_pred, zero_division=0)
    )
    metrics["recall"] = float(recall_score(y_true, y_pred, zero_division=0))
    metrics["f1"] = float(f1_score(y_true, y_pred, zero_division=0))
    metrics["confusion_matrix"] = confusion_matrix(y_true, y_pred).tolist()

    # Probability-based metrics where supported.
    try:
        y_prob = model.predict_proba(X)[:, 1]
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        metrics["average_precision"] = float(average_precision_score(y_true, y_prob))
    except Exception:
        metrics["roc_auc"] = None
        metrics["average_precision"] = None

    return metrics


def select_best_model(
    results: dict[str, dict[str, Any]],
    metric: str = "f1",
) -> str:
    """Select the best model by validation metric (default F1)."""
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
) -> dict[str, Any]:
    """Evaluate the selected model once on the held-out test partition.

    Returns metrics dict (test set used exactly once).
    """
    y_test_pred = model.predict(X_test)
    test_metrics = _compute_binary_metrics(y_test, y_pred=y_test_pred, model=model, X=X_test)
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
        "task": "binary_intrusion_detection",
        "target": TARGET_BINARY,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"\nSaved model: {model_path}")
    print(f"Saved preprocessor: {preprocessor_path}")
    print(f"Saved metadata: {metadata_path}")


def load_synthetic_binary_demo(events_path: str | Path) -> dict[str, Any]:
    """Build a synthetic binary classification demo from Member 3 events.

    Since the synthetic events.jsonl has no attack label, we create a
    *pseudo-label* based on event_type (network_flow = suspicious) purely
    to exercise the training pipeline end-to-end. This is NOT real-world
    performance and is labelled as such in output.
    """
    from data_loader import load_member3_events

    df = load_member3_events(events_path)
    df = df.copy()

    # Pseudo-label for smoke test only: network_flow -> attack (1), else normal (0).
    df[TARGET_BINARY] = (df["event_type"] == "network_flow").astype(int)

    feature_columns = identify_feature_columns(df, TARGET_BINARY, task_type="binary")

    # Use all data as train (smoke test; no held-out test with 6 rows).
    X = df[feature_columns]
    y = df[TARGET_BINARY]

    preprocessor = build_preprocessor(df, TARGET_BINARY, task_type="binary")
    preprocessor = fit_preprocessor(preprocessor, X)
    X_t = transform_preprocessor(preprocessor, X)
    feature_names = get_feature_names(preprocessor)

    models = get_binary_models()
    # Train on all data (smoke test; no validation split).
    for name, model in models.items():
        model.fit(X_t, y)

    return {
        "models": models,
        "preprocessor": preprocessor,
        "feature_names": feature_names,
        "n_samples": len(df),
        "label_distribution": y.value_counts().to_dict(),
        "is_smoke_test": True,
    }


def run_binary_pipeline(
    train_path: str | Path | None,
    test_path: str | Path | None,
    model_dir: str | Path,
    report_dir: str | Path,
    random_state: int = 42,
    validation_size: float = 0.2,
) -> dict[str, Any]:
    """Run the full binary detection pipeline.

    If train_path/test_path are None, runs the synthetic smoke test.
    """
    model_dir = Path(model_dir)
    report_dir = Path(report_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    if train_path is None or test_path is None:
        print("=== BINARY DETECTION — SYNTHETIC SMOKE TEST (not real performance) ===")
        demo = load_synthetic_binary_demo(
            Path(__file__).resolve().parents[2]
            / "data"
            / "demo-run"
            / "processed"
            / "events.jsonl"
        )
        print(f"\nSmoke test samples: {demo['n_samples']}")
        print(f"Label distribution: {demo['label_distribution']}")
        print(f"Feature count: {len(demo['feature_names'])}")
        print("\nModels trained on synthetic data (pipeline smoke test only).")
        print("UNSW-NB15 required for real training/evaluation.")
        return {
            "status": "smoke_test",
            "models": demo["models"],
            "preprocessor": demo["preprocessor"],
            "feature_names": demo["feature_names"],
        }

    from data_loader import load_unsw_nb15

    print("=== BINARY DETECTION — UNSW-NB15 (real training) ===")
    train_df, test_df = load_unsw_nb15(train_path, test_path)

    print(f"\nTraining rows: {len(train_df)}, Testing rows: {len(test_df)}")
    if TARGET_BINARY not in train_df.columns:
        raise ValueError(
            f"Target column {TARGET_BINARY!r} not found in training data. "
            f"Columns: {list(train_df.columns)}"
        )

    # Identify features once from training schema.
    feature_columns = identify_feature_columns(train_df, TARGET_BINARY, task_type="binary")
    print(f"Feature columns ({len(feature_columns)}): {feature_columns}")

    # Build + fit preprocessor on training data only.
    preprocessor = build_preprocessor(train_df, TARGET_BINARY, task_type="binary")
    preprocessor = fit_preprocessor(preprocessor, train_df[feature_columns])

    X_train_all = transform_preprocessor(preprocessor, train_df[feature_columns])
    y_train_all = train_df[TARGET_BINARY]
    feature_names = get_feature_names(preprocessor)

    # Transform test set once.
    X_test = transform_preprocessor(preprocessor, test_df[feature_columns])
    y_test = test_df[TARGET_BINARY]

    # Train/validation split from training data (stratified).
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_all,
        y_train_all,
        test_size=validation_size,
        random_state=random_state,
        stratify=y_train_all,
    )

    print(f"\nTrain/validation split: {len(X_train)} train / {len(X_val)} validation")

    # Train and compare models.
    models = get_binary_models(random_state=random_state)
    results = train_and_compare(X_train, y_train, X_val, y_val, models, random_state)

    # Select best model by validation F1.
    best_name = select_best_model(results, metric="f1")
    best_model = results[best_name]["model"]
    print(f"\nBest model (validation F1): {best_name}")

    # Evaluate once on held-out test partition.
    test_metrics = evaluate_on_test(best_model, X_test, y_test)
    print("\n=== Held-out test set evaluation (single pass) ===")
    for metric, value in test_metrics.items():
        if metric in ("confusion_matrix", "classification_report"):
            continue
        print(f"  {metric}: {value:.4f}" if value is not None else f"  {metric}: None")

    # Save artifacts.
    model_path = model_dir / "binary_model.joblib"
    preprocessor_path = model_dir / "binary_preprocessor.joblib"
    metadata_path = report_dir / "binary_model_metadata.json"
    save_model_artifacts(
        model=best_model,
        preprocessor=preprocessor,
        feature_names=feature_names,
        model_path=model_path,
        preprocessor_path=preprocessor_path,
        metadata_path=metadata_path,
        model_name=best_name,
        test_metrics=test_metrics,
    )

    # Save comparison report.
    comparison_lines = ["# Binary Model Comparison Report\n"]
    comparison_lines.append("| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Avg Precision |")
    comparison_lines.append("|-------|----------|-----------|--------|----|---------|---------------|")
    for name, result in results.items():
        m = result["validation_metrics"]
        comparison_lines.append(
            f"| {name} | {m['accuracy']:.4f} | {m['precision']:.4f} | "
            f"{m['recall']:.4f} | {m['f1']:.4f} | "
            f"{m['roc_auc'] if m['roc_auc'] is not None else 'N/A'} | "
            f"{m['average_precision'] if m['average_precision'] is not None else 'N/A'} |"
        )
    comparison_path = report_dir / "model_comparison.md"
    comparison_path.write_text("\n".join(comparison_lines), encoding="utf-8")
    print(f"\nSaved model comparison: {comparison_path}")

    # Save evaluation report.
    eval_lines = [
        "# Binary Intrusion Detection — Evaluation Report\n",
        f"## Selected model: {best_name}\n",
        "## Held-out test set metrics (single evaluation pass)\n",
    ]
    for metric, value in test_metrics.items():
        if metric == "confusion_matrix":
            eval_lines.append(f"### Confusion Matrix\n```\n{np.array(value)}\n```\n")
        elif metric == "classification_report":
            continue
        else:
            eval_lines.append(f"- {metric}: {value:.4f}" if value is not None else f"- {metric}: None")
    eval_path = report_dir / "evaluation_report.md"
    eval_path.write_text("\n".join(eval_lines), encoding="utf-8")
    print(f"Saved evaluation report: {eval_path}")

    return {
        "status": "complete",
        "best_model": best_name,
        "best_model_object": best_model,
        "preprocessor": preprocessor,
        "feature_names": feature_names,
        "test_metrics": test_metrics,
        "validation_results": {
            name: r["validation_metrics"] for name, r in results.items()
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 3: Binary Intrusion Detection training and evaluation."
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

    run_binary_pipeline(
        train_path=args.train,
        test_path=args.test,
        model_dir=args.model_dir,
        report_dir=args.report_dir,
        random_state=args.random_state,
        validation_size=args.validation_size,
    )


if __name__ == "__main__":
    main()
