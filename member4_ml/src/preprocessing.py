"""Reproducible preprocessing pipeline for Member 4 ML layer.

Consumes normalized events (Member 3 events.jsonl schema) or UNSW-NB15
train/test CSVs. Removes identifier and leakage-prone fields, handles
missing values, encodes categoricals, and scales numerics. Fits only on
training data; applies the same transform to validation and testing.

Run the self-check from the TRUST repo root:
  $env:PYTHONPATH = "src;member4_ml/src"
  python member4_ml/src/preprocessing.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# Columns that are identifiers or metadata and must never enter the model.
IDENTIFIER_COLUMNS = {
    "id",
    "event_id",
    "source_record_id",
    "evidence_id",
    "ingested_at",
}

# Columns that leak the target and must be excluded depending on task.
LEAKAGE_COLUMNS_BINARY = {"attack_cat"}  # attack_cat reveals the binary answer
LEAKAGE_COLUMNS_MULTICLASS = {"label"}  # label reveals the multiclass answer

# Target column names recognized in UNSW-NB15.
TARGET_BINARY = "label"
TARGET_MULTICLASS = "attack_cat"


def identify_feature_columns(
    df: pd.DataFrame,
    target_col: str,
    task_type: str = "binary",
) -> list[str]:
    """Return the list of columns safe to use as model features.

    Removes:
      - the target column,
      - identifier/metadata columns,
      - leakage-prone columns for the given task type.

    Parameters
    ----------
    df : pd.DataFrame
        Input data.
    target_col : str
        Name of the target column to exclude.
    task_type : {"binary", "multiclass"}
        Determines which leakage columns to drop.

    Returns
    -------
    list[str]
        Safe feature column names, in df column order.
    """
    excluded = set(IDENTIFIER_COLUMNS)
    if target_col and target_col in df.columns:
        excluded.add(target_col)

    if task_type == "binary":
        excluded |= LEAKAGE_COLUMNS_BINARY
    elif task_type == "multiclass":
        excluded |= LEAKAGE_COLUMNS_MULTICLASS
    else:
        raise ValueError(f"Unknown task_type: {task_type!r}. Use 'binary' or 'multiclass'.")

    return [c for c in df.columns if c not in excluded]


def split_numeric_categorical(
    df: pd.DataFrame,
    feature_columns: list[str],
) -> tuple[list[str], list[str]]:
    """Split feature columns into numeric and categorical lists."""
    numeric = [c for c in feature_columns if pd.api.types.is_numeric_dtype(df[c])]
    categorical = [c for c in feature_columns if c not in numeric]
    return numeric, categorical


def build_preprocessor(
    df: pd.DataFrame,
    target_col: str,
    task_type: str = "binary",
    scale_numeric: bool = True,
) -> ColumnTransformer:
    """Build a scikit-learn ColumnTransformer preprocessing pipeline.

    Numeric pipeline: SimpleImputer(median) -> [StandardScaler if scale_numeric].
    Categorical pipeline: SimpleImputer(most_frequent) -> OneHotEncoder.

    The transformer is NOT fitted here. Call fit_preprocessor() to fit on
    training data only.

    Parameters
    ----------
    df : pd.DataFrame
        Input data (used only to infer column types, not to fit).
    target_col : str
        Target column name (excluded from features).
    task_type : {"binary", "multiclass"}
        Task type for leakage prevention.
    scale_numeric : bool
        Whether to apply StandardScaler to numeric features.

    Returns
    -------
    ColumnTransformer
        Unfitted preprocessor.
    """
    feature_columns = identify_feature_columns(df, target_col, task_type)
    numeric_cols, categorical_cols = split_numeric_categorical(df, feature_columns)

    numeric_steps: list[tuple[str, Any]] = [("imputer", SimpleImputer(strategy="median"))]
    if scale_numeric:
        numeric_steps.append(("scaler", StandardScaler()))
    numeric_pipeline = Pipeline(steps=numeric_steps)

    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            (
                "encoder",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
            ),
        ]
    )

    transformers: list[tuple[str, Any, list[str]]] = []
    if numeric_cols:
        transformers.append(("numeric", numeric_pipeline, numeric_cols))
    if categorical_cols:
        transformers.append(("categorical", categorical_pipeline, categorical_cols))

    if not transformers:
        raise ValueError(
            "No feature columns remain after removing identifiers and leakage fields. "
            "Check the input schema."
        )

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")
    return preprocessor


def fit_preprocessor(
    preprocessor: ColumnTransformer,
    X_train: pd.DataFrame,
) -> ColumnTransformer:
    """Fit the preprocessor on training data only.

    Must be called before transform_preprocessor(). Never fit on validation
    or test data.
    """
    return preprocessor.fit(X_train)


def transform_preprocessor(
    preprocessor: ColumnTransformer,
    X: pd.DataFrame,
) -> np.ndarray:
    """Transform data using a fitted preprocessor.

    Raises a clear error if the preprocessor has not been fitted.
    """
    try:
        return preprocessor.transform(X)
    except Exception as exc:
        raise RuntimeError(
            "Preprocessor has not been fitted. Call fit_preprocessor() on "
            "training data first."
        ) from exc


def get_feature_names(preprocessor: ColumnTransformer) -> list[str]:
    """Return the output feature names after preprocessing.

    Requires the preprocessor to be fitted.
    """
    try:
        return preprocessor.get_feature_names_out().tolist()
    except Exception as exc:
        raise RuntimeError(
            "Preprocessor has not been fitted. Call fit_preprocessor() first."
        ) from exc


def save_preprocessor(preprocessor: ColumnTransformer, path: str | Path) -> None:
    """Save a fitted preprocessor to disk with joblib."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(preprocessor, path)


def load_preprocessor(path: str | Path) -> ColumnTransformer:
    """Load a fitted preprocessor from disk."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Preprocessor file not found: {path}")
    return joblib.load(path)


def separate_X_y(
    df: pd.DataFrame,
    target_col: str,
) -> tuple[pd.DataFrame, pd.Series]:
    """Split a DataFrame into features X and target y.

    Raises a clear error if the target column is missing.
    """
    if target_col not in df.columns:
        raise ValueError(
            f"Target column {target_col!r} not found in data. "
            f"Available columns: {list(df.columns)}"
        )
    X = df.drop(columns=[target_col])
    y = df[target_col]
    return X, y


def stratified_split(
    X: pd.DataFrame,
    y: pd.Series,
    validation_size: float = 0.2,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Split X/y into train and validation sets with stratification.

    Falls back to a non-stratified split if a class has too few members
    to stratify.
    """
    from sklearn.model_selection import train_test_split

    try:
        return train_test_split(
            X,
            y,
            test_size=validation_size,
            random_state=random_state,
            stratify=y,
        )
    except ValueError:
        # Stratification failed (e.g., a class has only 1 member).
        return train_test_split(
            X,
            y,
            test_size=validation_size,
            random_state=random_state,
        )


def preprocess_train_validation_test(
    train_df: pd.DataFrame,
    validation_df: pd.DataFrame,
    test_df: pd.DataFrame,
    target_col: str,
    task_type: str = "binary",
    scale_numeric: bool = True,
) -> dict[str, Any]:
    """End-to-end preprocessing for train/validation/test.

    Fits the preprocessor on training data only, then transforms all three
    splits. Returns a dict with transformed arrays, the fitted preprocessor,
    and feature names.

    Returns
    -------
    dict with keys:
      X_train, X_validation, X_test : np.ndarray
      y_train, y_validation, y_test : pd.Series
      preprocessor : ColumnTransformer (fitted)
      feature_names : list[str]
      feature_columns : list[str]  (input feature column names)
    """
    feature_columns = identify_feature_columns(train_df, target_col, task_type)

    X_train = train_df[feature_columns]
    y_train = train_df[target_col]
    X_validation = validation_df[feature_columns]
    y_validation = validation_df[target_col]
    X_test = test_df[feature_columns]
    y_test = test_df[target_col]

    preprocessor = build_preprocessor(
        train_df, target_col, task_type=task_type, scale_numeric=scale_numeric
    )
    preprocessor = fit_preprocessor(preprocessor, X_train)

    X_train_t = transform_preprocessor(preprocessor, X_train)
    X_validation_t = transform_preprocessor(preprocessor, X_validation)
    X_test_t = transform_preprocessor(preprocessor, X_test)
    feature_names = get_feature_names(preprocessor)

    return {
        "X_train": X_train_t,
        "X_validation": X_validation_t,
        "X_test": X_test_t,
        "y_train": y_train,
        "y_validation": y_validation,
        "y_test": y_test,
        "preprocessor": preprocessor,
        "feature_names": feature_names,
        "feature_columns": feature_columns,
    }


def demo_with_synthetic_events(events_path: str | Path) -> None:
    """Self-check: run preprocessing on Member 3 synthetic events.jsonl.

    The synthetic data has no attack label, so this demonstrates the
    transform (identifier removal, missing-value handling, encoding,
    scaling) without training a model. Prints shapes and output feature
    names to verify correctness.
    """
    from data_loader import load_member3_events

    print("=" * 60)
    print("Phase 2 Preprocessing — self-check on synthetic events.jsonl")
    print("=" * 60)

    df = load_member3_events(events_path)
    print(f"\nInput shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")

    # No target in synthetic data: demonstrate feature identification only.
    target_col = None
    task_type = "binary"
    feature_columns = identify_feature_columns(df, target_col, task_type)
    print(f"\nFeature columns (identifiers removed): {feature_columns}")

    numeric_cols, categorical_cols = split_numeric_categorical(df, feature_columns)
    print(f"Numeric columns: {numeric_cols}")
    print(f"Categorical columns: {categorical_cols}")

    preprocessor = build_preprocessor(df, target_col or "none", task_type=task_type)
    preprocessor = fit_preprocessor(preprocessor, df[feature_columns])

    X_transformed = transform_preprocessor(preprocessor, df[feature_columns])
    feature_names = get_feature_names(preprocessor)

    print(f"\nTransformed shape: {X_transformed.shape}")
    print(f"Output feature names ({len(feature_names)}):")
    for name in feature_names:
        print(f"  - {name}")

    # Verify no identifier columns leaked into output.
    leaked = [c for c in IDENTIFIER_COLUMNS if c in feature_names]
    if leaked:
        print(f"\nERROR: identifier columns leaked into features: {leaked}")
    else:
        print("\nOK: no identifier columns in output features.")

    # Verify finite values (imputation worked).
    if np.isfinite(X_transformed).all():
        print("OK: all transformed values are finite (missing values imputed).")
    else:
        print("WARNING: non-finite values present in transformed output.")

    print("\nPreprocessing self-check complete.")


if __name__ == "__main__":
    import sys

    TRUST_ROOT = Path(__file__).resolve().parents[2]
    EVENTS_PATH = TRUST_ROOT / "data" / "demo-run" / "processed" / "events.jsonl"

    if len(sys.argv) > 1:
        EVENTS_PATH = Path(sys.argv[1])

    demo_with_synthetic_events(EVENTS_PATH)
