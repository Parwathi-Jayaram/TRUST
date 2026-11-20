"""Phase 7 — Anomaly Detection (Member 4).

Investigates whether an anomaly-detection component adds value to the
SOC investigation workflow. Implements Isolation Forest as a simple,
unsupervised baseline.

Key distinction (per spec):
  - A supervised classifier predicts from labelled examples (normal vs attack).
  - An anomaly detector identifies behaviour that differs from its learned
    reference — an anomaly is NOT automatically malicious.
  - Only retain anomaly detection if it adds measurable value.

Train strategy: fit Isolation Forest on normal (non-attack) events only,
so it learns what "normal" looks like and flags deviations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from preprocessing import (
    build_preprocessor,
    fit_preprocessor,
    transform_preprocessor,
    get_feature_names,
    identify_feature_columns,
    TARGET_BINARY,
)


class AnomalyDetector:
    """Isolation Forest anomaly detector for network events.

    Fits on normal events only. Produces an anomaly score per event where
    lower = more anomalous. Provides a boolean anomaly flag at a chosen
    threshold and a raw anomaly score.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        max_samples: str | int = "auto",
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        self.model: IsolationForest | None = None
        self.preprocessor: Any = None
        self.feature_names: list[str] = []
        self.feature_columns: list[str] = []
        self.is_fitted = False

    def fit(
        self,
        df: pd.DataFrame,
        target_col: str,
        normal_label: Any = 0,
    ) -> "AnomalyDetector":
        """Fit the detector on normal events only.

        Parameters
        ----------
        df : pd.DataFrame
            Full labelled dataset.
        target_col : str
            Name of the label column (e.g. `label`).
        normal_label : any
            Value in target_col that represents "normal" (default 0).
        """
        if target_col not in df.columns:
            raise ValueError(
                f"Target column {target_col!r} not found. Columns: {list(df.columns)}"
            )

        # Train on normal events only — learn the reference of "normal".
        normal_df = df[df[target_col] == normal_label].copy()
        if len(normal_df) == 0:
            raise ValueError("No normal events found to train the anomaly detector.")

        self.feature_columns = identify_feature_columns(
            normal_df, target_col, task_type="binary"
        )
        X = normal_df[self.feature_columns]

        self.preprocessor = build_preprocessor(
            normal_df, target_col, task_type="binary"
        )
        self.preprocessor = fit_preprocessor(self.preprocessor, X)
        X_t = transform_preprocessor(self.preprocessor, X)
        self.feature_names = get_feature_names(self.preprocessor)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_t)
        self.is_fitted = True
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """Return anomaly scores for events.

        Lower scores = more anomalous. Uses IsolationForest.decision_function
        (higher = more normal), so we negate it so higher = more anomalous
        for intuitive risk scoring.

        Returns
        -------
        np.ndarray of anomaly scores (higher = more anomalous).
        """
        if not self.is_fitted:
            raise RuntimeError("AnomalyDetector is not fitted. Call fit() first.")

        X = df[self.feature_columns]
        X_t = transform_preprocessor(self.preprocessor, X)
        # decision_function: higher = more normal. Negate so higher = more anomalous.
        normal_scores = self.model.decision_function(X_t)
        anomaly_scores = -normal_scores
        return anomaly_scores

    def predict(self, df: pd.DataFrame, threshold: float | None = None) -> np.ndarray:
        """Return boolean anomaly flags.

        Uses IsolationForest.predict (1 = normal, -1 = anomaly) converted
        to boolean (True = anomaly). If threshold is provided, uses the
        raw anomaly score threshold instead.
        """
        if not self.is_fitted:
            raise RuntimeError("AnomalyDetector is not fitted. Call fit() first.")

        X = df[self.feature_columns]
        X_t = transform_preprocessor(self.preprocessor, X)

        if threshold is not None:
            scores = self.score(df)
            return scores >= threshold

        raw = self.model.predict(X_t)  # 1 = normal, -1 = anomaly
        return raw == -1

    def save(self, model_path: str | Path, preprocessor_path: str | Path) -> None:
        """Save the fitted detector and preprocessor."""
        model_path = Path(model_path)
        preprocessor_path = Path(preprocessor_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        preprocessor_path.parent.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.model, model_path)
        joblib.dump(self.preprocessor, preprocessor_path)

    @classmethod
    def load(
        cls,
        model_path: str | Path,
        preprocessor_path: str | Path,
        feature_columns: list[str],
        feature_names: list[str],
        contamination: float = 0.1,
    ) -> "AnomalyDetector":
        """Load a saved detector."""
        model = joblib.load(model_path)
        preprocessor = joblib.load(preprocessor_path)

        detector = cls(contamination=contamination)
        detector.model = model
        detector.preprocessor = preprocessor
        detector.feature_columns = feature_columns
        detector.feature_names = feature_names
        detector.is_fitted = True
        return detector


def compare_supervised_vs_anomaly(
    y_true: np.ndarray | pd.Series,
    supervised_pred: np.ndarray,
    anomaly_pred: np.ndarray,
) -> dict[str, Any]:
    """Compare supervised classifier vs anomaly detector outputs.

    Returns counts of:
      - both agree normal
      - both agree attack/anomaly
      - supervised says attack, anomaly says normal
      - anomaly says anomaly, supervised says normal

    Helps decide whether anomaly detection adds value beyond the
    supervised classifier.
    """
    y_true = np.asarray(y_true)
    supervised_pred = np.asarray(supervised_pred)
    anomaly_pred = np.asarray(anomaly_pred)

    # Treat anomaly=True as "positive" for comparison.
    both_normal = int(((supervised_pred == 0) & (~anomaly_pred)).sum())
    both_attack = int(((supervised_pred == 1) & anomaly_pred).sum())
    sup_attack_anom_normal = int(((supervised_pred == 1) & (~anomaly_pred)).sum())
    sup_normal_anom_attack = int(((supervised_pred == 0) & anomaly_pred).sum())

    # Anomaly-only detections that are actually attacks (value add).
    anomaly_only_attacks = int(
        ((supervised_pred == 0) & anomaly_pred & (y_true == 1)).sum()
    )
    # Anomaly false positives (normal flagged).
    anomaly_fp_on_normal = int(
        ((supervised_pred == 0) & anomaly_pred & (y_true == 0)).sum()
    )

    return {
        "both_normal": both_normal,
        "both_attack": both_attack,
        "supervised_attack_anomaly_normal": sup_attack_anom_normal,
        "supervised_normal_anomaly_attack": sup_normal_anom_attack,
        "anomaly_only_attacks_caught": anomaly_only_attacks,
        "anomaly_false_positives_on_normal": anomaly_fp_on_normal,
    }


if __name__ == "__main__":
    # Self-check on synthetic data.
    import sys
    from pathlib import Path as _P

    sys.path.insert(0, str(_P(__file__).resolve().parents[1]))
    from data_loader import load_member3_events

    TRUST_ROOT = _P(__file__).resolve().parents[2]
    EVENTS_PATH = TRUST_ROOT / "data" / "demo-run" / "processed" / "events.jsonl"

    print("=" * 60)
    print("Phase 7 Anomaly Detection — self-check on synthetic data")
    print("=" * 60)

    df = load_member3_events(EVENTS_PATH)
    df[TARGET_BINARY] = (df["event_type"] == "network_flow").astype(int)
    print(f"\nSamples: {len(df)}, label distribution: {df[TARGET_BINARY].value_counts().to_dict()}")

    detector = AnomalyDetector(contamination=0.2, random_state=42)
    detector.fit(df, TARGET_BINARY, normal_label=0)

    scores = detector.score(df)
    anomaly_flags = detector.predict(df)

    print(f"\nAnomaly scores (higher = more anomalous): {np.round(scores, 3).tolist()}")
    print(f"Anomaly flags: {anomaly_flags.tolist()}")
    print(f"Feature count: {len(detector.feature_names)}")

    # Comparison (supervised pseudo-label vs anomaly).
    comparison = compare_supervised_vs_anomaly(
        y_true=df[TARGET_BINARY].values,
        supervised_pred=df[TARGET_BINARY].values,
        anomaly_pred=anomaly_flags,
    )
    print("\nSupervised vs Anomaly comparison:")
    for k, v in comparison.items():
        print(f"  {k}: {v}")

    print("\nAnomaly detection self-check complete.")
    print(
        "\nNote: An anomaly is not automatically malicious. Retain only if "
        "it adds measurable investigation value."
    )
