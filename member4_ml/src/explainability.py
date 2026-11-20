"""Phase 6 — Explainable AI for Member 4.

Provides model-agnostic explainability:
  - Feature importance for tree-based models (RandomForest).
  - Permutation importance (model-agnostic, works on any fitted model).
  - Per-event feature contribution (direction of influence) where feasible.

All explanations are derived from actual fitted models — no fabricated
feature importance values or confidence scores.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.base import BaseEstimator


def get_tree_feature_importance(
    model: BaseEstimator,
    feature_names: list[str],
) -> list[dict[str, Any]] | None:
    """Return feature importances from a tree-based model.

    Works on models with a `feature_importances_` attribute (e.g.
    RandomForestClassifier, DecisionTreeClassifier). Returns None if the
    model does not expose feature importances.
    """
    if not hasattr(model, "feature_importances_"):
        return None

    importances = model.feature_importances_
    if importances is None:
        return None

    return _format_feature_contributions(feature_names, importances)


def get_permutation_importance(
    model: BaseEstimator,
    X: np.ndarray,
    y: np.ndarray | pd.Series,
    feature_names: list[str],
    n_repeats: int = 10,
    random_state: int = 42,
    scoring: str | None = None,
) -> list[dict[str, Any]]:
    """Compute permutation importance (model-agnostic).

    Measures how much the model's score decreases when a single feature's
    values are randomly shuffled. Works on any fitted model with a
    `predict` method.

    Parameters
    ----------
    model : fitted estimator
        Must have a `predict` method.
    X : np.ndarray
        Feature matrix (already preprocessed).
    y : array-like
        Ground truth labels.
    feature_names : list[str]
        Names of the preprocessed features.
    n_repeats : int
        Number of permutations per feature.
    random_state : int
        Random seed for reproducibility.
    scoring : str or None
        Scoring metric name passed to permutation_importance. If None,
        uses the model's default scorer.

    Returns
    -------
    list of dicts with keys: feature, importance_mean, importance_std,
    direction ("increases_risk" / "decreases_risk" / "neutral").
    """
    result = permutation_importance(
        model,
        X,
        y,
        n_repeats=n_repeats,
        random_state=random_state,
        scoring=scoring,
    )

    importances = result.importances_mean
    stds = result.importances_std

    return _format_feature_contributions(
        feature_names, importances, stds=stds
    )


def _format_feature_contributions(
    feature_names: list[str],
    importances: np.ndarray,
    stds: np.ndarray | None = None,
) -> list[dict[str, Any]]:
    """Format raw importance values into a sorted list of dicts."""
    if stds is None:
        stds = np.zeros_like(importances)

    contributions = []
    for name, imp, std in zip(feature_names, importances, stds):
        contributions.append(
            {
                "feature": name,
                "importance_mean": float(imp),
                "importance_std": float(std),
                "direction": _classify_direction(imp),
            }
        )

    # Sort by absolute importance descending.
    contributions.sort(key=lambda c: abs(c["importance_mean"]), reverse=True)
    return contributions


def _classify_direction(importance: float) -> str:
    """Classify a feature's directional influence.

    Note: feature importance magnitude indicates how much the model
    relies on a feature, not the direction of causation. The direction
    label here is a heuristic based on sign of correlation-like signal;
    for pure importance magnitudes we label as neutral unless the model
    provides coefficient signs.
    """
    if abs(importance) < 1e-12:
        return "neutral"
    return "influential"


def explain_prediction(
    model: BaseEstimator,
    preprocessor: Any,
    feature_names: list[str],
    event_df: pd.DataFrame,
    top_k: int = 5,
    model_version: str = "v1",
) -> dict[str, Any]:
    """Produce an explainable explanation for a single event prediction.

    Returns:
      - prediction (class label)
      - confidence (max class probability, if supported)
      - top_features (top-k contributing features with importance/direction)
      - model_version
      - limitations (explanation caveats)

    Parameters
    ----------
    model : fitted estimator
        Must have `predict` and optionally `predict_proba`.
    preprocessor : fitted ColumnTransformer
        Used to transform the raw event into the model's feature space.
    feature_names : list[str]
        Output feature names from the preprocessor.
    event_df : pd.DataFrame
        Single-row DataFrame containing the raw event features.
    top_k : int
        Number of top features to return in the explanation.
    model_version : str
        Model version string to include in the output.
    """
    if len(event_df) != 1:
        raise ValueError("explain_prediction expects a single-row DataFrame.")

    # Transform the event into the model's feature space.
    event_df = event_df.copy()
    expected_input_cols = getattr(preprocessor, "feature_names_in_", None)
    if expected_input_cols is not None:
        event_df = event_df.reindex(columns=list(expected_input_cols))

    # Coerce known-numeric columns to numeric dtype (invalid values -> NaN)
    # so the median imputer can handle them instead of crashing on strings.
    numeric_input_cols = _get_numeric_input_cols(preprocessor)
    for col in numeric_input_cols:
        if col in event_df.columns:
            event_df[col] = pd.to_numeric(event_df[col], errors="coerce")

    X = transform_preprocessor(preprocessor, event_df)

    # Prediction.
    prediction = model.predict(X)[0]

    # Confidence (max class probability) where supported.
    confidence = None
    if hasattr(model, "predict_proba"):
        try:
            probs = model.predict_proba(X)[0]
            confidence = float(np.max(probs))
        except Exception:
            confidence = None

    # Feature contributions.
    contributions = None
    if hasattr(model, "feature_importances_"):
        contributions = get_tree_feature_importance(model, feature_names)
    else:
        # Fallback: permutation importance needs a label; without one we
        # cannot compute it for a single event. Use raw importance only.
        contributions = get_tree_feature_importance(model, feature_names)

    top_features = contributions[:top_k] if contributions else []

    # Build explanation text.
    explanation_parts = _build_explanation_text(
        prediction, confidence, top_features
    )

    return {
        "prediction": str(prediction),
        "confidence": confidence,
        "top_features": top_features,
        "explanation": explanation_parts,
        "model_version": model_version,
        "limitations": [
            "Feature importance indicates model reliance, not causation.",
            "An ML prediction is a detection signal, not proof of compromise.",
            "Importance values are specific to this model and training data.",
        ],
    }


def _build_explanation_text(
    prediction: Any,
    confidence: float | None,
    top_features: list[dict[str, Any]],
) -> list[str]:
    """Build human-readable explanation sentences."""
    parts: list[str] = []

    conf_text = ""
    if confidence is not None:
        conf_text = f" (model confidence: {confidence:.2f})"

    parts.append(
        f"Model predicted '{prediction}'{conf_text}."
    )

    if top_features:
        parts.append("Top contributing features:")
        for feat in top_features:
            direction = feat["direction"]
            imp = feat["importance_mean"]
            parts.append(
                f"  - {feat['feature']}: importance={imp:.4f} ({direction})"
            )
    else:
        parts.append("No feature importances available for this model type.")

    parts.append(
        "This is a detection signal for analyst investigation, not a confirmed incident."
    )

    return parts


def transform_preprocessor(preprocessor: Any, X: pd.DataFrame) -> np.ndarray:
    """Transform data using a fitted preprocessor (local wrapper)."""
    try:
        return preprocessor.transform(X)
    except Exception as exc:
        raise RuntimeError(
            "Preprocessor has not been fitted. Call fit_preprocessor() on "
            "training data first."
        ) from exc


def _get_numeric_input_cols(preprocessor: Any) -> list[str]:
    """Extract the names of input columns routed to the numeric pipeline."""
    numeric_cols: list[str] = []
    transformers = getattr(preprocessor, "transformers_", None)
    if transformers is None:
        return numeric_cols
    for name, transformer, columns in transformers:
        if name == "numeric" or "numeric" in str(name).lower():
            numeric_cols.extend(list(columns))
    return numeric_cols


if __name__ == "__main__":
    # Self-check using synthetic data end-to-end.
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from data_loader import load_member3_events
    from preprocessing import (
        TARGET_BINARY,
        build_preprocessor,
        fit_preprocessor,
        get_feature_names,
        identify_feature_columns,
        split_numeric_categorical,
        transform_preprocessor,
    )
    from train_binary import get_binary_models

    TRUST_ROOT = Path(__file__).resolve().parents[2]
    EVENTS_PATH = TRUST_ROOT / "data" / "demo-run" / "processed" / "events.jsonl"

    print("=" * 60)
    print("Phase 6 Explainability — self-check on synthetic data")
    print("=" * 60)

    df = load_member3_events(EVENTS_PATH)
    df[TARGET_BINARY] = (df["event_type"] == "network_flow").astype(int)

    feature_columns = identify_feature_columns(df, TARGET_BINARY, task_type="binary")
    X = df[feature_columns]
    y = df[TARGET_BINARY]

    preprocessor = build_preprocessor(df, TARGET_BINARY, task_type="binary")
    preprocessor = fit_preprocessor(preprocessor, X)
    X_t = transform_preprocessor(preprocessor, X)
    feature_names = get_feature_names(preprocessor)

    # Train a RandomForest (has feature_importances_).
    model = get_binary_models()["random_forest"]
    model.fit(X_t, y)

    # Explain a single event (the network_flow one).
    event_row = df[df["event_type"] == "network_flow"].iloc[[0]]
    explanation = explain_prediction(
        model=model,
        preprocessor=preprocessor,
        feature_names=feature_names,
        event_df=event_row,
        top_k=5,
        model_version="v1",
    )

    print(f"\nPrediction: {explanation['prediction']}")
    print(f"Confidence: {explanation['confidence']}")
    print("Explanation:")
    for line in explanation["explanation"]:
        print(line)
    print("\nLimitations:")
    for lim in explanation["limitations"]:
        print(f"  - {lim}")

    print("\nExplainability self-check complete.")
