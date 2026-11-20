"""Phase 5 — Model Evaluation utilities for Member 4.

Provides:
  - Binary classification metrics (accuracy, precision, recall, F1,
    macro F1, weighted F1, ROC-AUC, PR-AUC, FPR, FNR).
  - Confusion matrix computation.
  - Threshold selection on validation data (precision-recall trade-off).
  - Per-class metrics for multiclass evaluation.

All metrics computed from actual model outputs — no fabricated results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    average_precision_score,
    precision_recall_curve,
    roc_curve,
)


def compute_binary_metrics(
    y_true: np.ndarray | pd.Series,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None,
) -> dict[str, Any]:
    """Compute standard binary classification metrics.

    Parameters
    ----------
    y_true : array-like
        Ground truth labels (0 = normal, 1 = attack).
    y_pred : array-like
        Predicted labels.
    y_prob : array-like, optional
        Predicted probabilities for the positive class. Used for
        ROC-AUC and PR-AUC. If None, those metrics are set to None.

    Returns
    -------
    dict with keys: accuracy, precision, recall, f1, macro_f1,
    weighted_f1, fpr, fnr, roc_auc, average_precision,
    confusion_matrix (as nested list), tn, fp, fn, tp.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    total = len(y_true)
    metrics: dict[str, Any] = {}
    metrics["accuracy"] = float(accuracy_score(y_true, y_pred))
    metrics["precision"] = float(precision_score(y_true, y_pred, zero_division=0))
    metrics["recall"] = float(recall_score(y_true, y_pred, zero_division=0))
    metrics["f1"] = float(f1_score(y_true, y_pred, zero_division=0))
    metrics["macro_f1"] = float(
        f1_score(y_true, y_pred, average="macro", zero_division=0)
    )
    metrics["weighted_f1"] = float(
        f1_score(y_true, y_pred, average="weighted", zero_division=0)
    )

    # False Positive Rate and False Negative Rate (SOC-relevant).
    metrics["fpr"] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    metrics["fnr"] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    metrics["tn"] = int(tn)
    metrics["fp"] = int(fp)
    metrics["fn"] = int(fn)
    metrics["tp"] = int(tp)
    metrics["confusion_matrix"] = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    metrics["total_samples"] = int(total)

    if y_prob is not None:
        y_prob = np.asarray(y_prob)
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        except Exception:
            metrics["roc_auc"] = None
        try:
            metrics["average_precision"] = float(
                average_precision_score(y_true, y_prob)
            )
        except Exception:
            metrics["average_precision"] = None
    else:
        metrics["roc_auc"] = None
        metrics["average_precision"] = None

    return metrics


def compute_multiclass_metrics(
    y_true: np.ndarray | pd.Series,
    y_pred: np.ndarray,
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """Compute per-class and aggregate multiclass metrics."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    metrics: dict[str, Any] = {}
    metrics["accuracy"] = float(accuracy_score(y_true, y_pred))
    metrics["macro_f1"] = float(
        f1_score(y_true, y_pred, average="macro", zero_division=0)
    )
    metrics["weighted_f1"] = float(
        f1_score(y_true, y_pred, average="weighted", zero_division=0)
    )
    metrics["macro_precision"] = float(
        precision_score(y_true, y_pred, average="macro", zero_division=0)
    )
    metrics["macro_recall"] = float(
        recall_score(y_true, y_pred, average="macro", zero_division=0)
    )
    metrics["confusion_matrix"] = confusion_matrix(
        y_true, y_pred, labels=labels
    ).tolist()
    metrics["confusion_matrix_labels"] = labels

    # Per-class precision/recall/f1.
    per_class = precision_recall_f1_support(y_true, y_pred, labels=labels)
    metrics["per_class"] = per_class

    # Classification report as text.
    try:
        metrics["classification_report"] = classification_report(
            y_true, y_pred, labels=labels, zero_division=0, output_dict=True
        )
    except Exception:
        metrics["classification_report"] = None

    return metrics


def precision_recall_f1_support(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: list[str] | None = None,
) -> dict[str, dict[str, float]]:
    """Return per-class precision, recall, f1, support."""
    from sklearn.metrics import precision_recall_f1_score as _prfs

    precision, recall, f1, support = _prfs(
        y_true, y_pred, labels=labels, zero_division=0, average=None
    )
    if labels is None:
        labels = [str(i) for i in range(len(precision))]

    result: dict[str, dict[str, float]] = {}
    for i, label in enumerate(labels):
        result[str(label)] = {
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
        }
    return result


def select_threshold(
    y_true: np.ndarray | pd.Series,
    y_prob: np.ndarray,
    objective: str = "f1",
    n_thresholds: int = 100,
) -> dict[str, Any]:
    """Select a decision threshold on validation data.

    Sweeps thresholds from 0 to 1 and picks the one optimizing the stated
    objective. The chosen threshold is documented, not re-tuned on test.

    Parameters
    ----------
    y_true : array-like
        Ground truth labels.
    y_prob : array-like
        Predicted probabilities for the positive class.
    objective : {"f1", "precision", "recall", "balanced"}
        Metric to optimize. "balanced" maximizes (precision + recall) / 2.
    n_thresholds : int
        Number of candidate thresholds to test.

    Returns
    -------
    dict with keys: best_threshold, best_score, objective, threshold_curve
    (list of {threshold, precision, recall, f1}).
    """
    y_true = np.asarray(y_true)
    y_prob = np.asarray(y_prob)

    thresholds = np.linspace(0.0, 1.0, n_thresholds)
    curve: list[dict[str, Any]] = []

    best_threshold = 0.5
    best_score = -1.0

    for thresh in thresholds:
        y_pred = (y_prob >= thresh).astype(int)
        prec = float(precision_score(y_true, y_pred, zero_division=0))
        rec = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))

        curve.append(
            {
                "threshold": float(thresh),
                "precision": prec,
                "recall": rec,
                "f1": f1,
            }
        )

        if objective == "f1":
            score = f1
        elif objective == "precision":
            score = prec
        elif objective == "recall":
            score = rec
        elif objective == "balanced":
            score = (prec + rec) / 2.0
        else:
            raise ValueError(
                f"Unknown objective: {objective!r}. "
                "Use 'f1', 'precision', 'recall', or 'balanced'."
            )

        if score > best_score:
            best_score = score
            best_threshold = float(thresh)

    return {
        "best_threshold": best_threshold,
        "best_score": float(best_score),
        "objective": objective,
        "threshold_curve": curve,
    }


def evaluate_with_threshold(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray | pd.Series,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Evaluate a model at a specific decision threshold.

    Returns metrics plus predictions and probabilities.
    """
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= threshold).astype(int)
    metrics = compute_binary_metrics(y_test, y_pred, y_prob)
    metrics["threshold_used"] = float(threshold)
    metrics["predictions"] = y_pred.tolist()
    metrics["probabilities"] = y_prob.tolist()
    return metrics


def save_metrics_report(
    metrics: dict[str, Any],
    path: str | Path,
    model_name: str | None = None,
    dataset_name: str | None = None,
) -> None:
    """Save metrics dict to a JSON report file (confusion matrix included)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {}
    if model_name:
        report["model_name"] = model_name
    if dataset_name:
        report["dataset"] = dataset_name
    report["metrics"] = metrics

    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def print_metrics_summary(metrics: dict[str, Any], title: str = "Metrics") -> None:
    """Print a human-readable metrics summary to stdout."""
    print(f"\n=== {title} ===")
    for key in (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "macro_f1",
        "weighted_f1",
        "fpr",
        "fnr",
        "roc_auc",
        "average_precision",
    ):
        value = metrics.get(key)
        if value is not None:
            print(f"  {key}: {value:.4f}")
        else:
            print(f"  {key}: None")
    cm = metrics.get("confusion_matrix")
    if cm is not None:
        print("  confusion_matrix:")
        for row in cm:
            print(f"    {row}")


if __name__ == "__main__":
    # Self-check with synthetic data.
    rng = np.random.RandomState(42)
    n = 200
    y_true = rng.randint(0, 2, size=n)
    y_prob = rng.rand(n)
    y_pred = (y_prob >= 0.5).astype(int)

    metrics = compute_binary_metrics(y_true, y_pred, y_prob)
    print_metrics_summary(metrics, "Self-check binary metrics")

    threshold_result = select_threshold(y_true, y_prob, objective="f1")
    print(f"\nSelected threshold (F1 objective): {threshold_result['best_threshold']:.3f}")
    print(f"Best F1 score: {threshold_result['best_score']:.4f}")
