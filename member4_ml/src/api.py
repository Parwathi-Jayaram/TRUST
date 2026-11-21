"""Phase 10 — FastAPI inference API for Member 4 ML layer.

Exposes the trained binary intrusion-detection model over HTTP so Member 1
(backend) and Member 5 (dashboard) can query predictions without understanding
training internals.

Endpoints:
  GET  /health          — service liveness + model loaded state
  GET  /metadata        — model name, version, task, feature count/names
  POST /predict         — single-event inference → structured result
  POST /predict-batch   — batch inference → list of structured results

Run:
  $env:PYTHONPATH = "src;member4_ml/src"
  uvicorn api:app --reload --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from predict import (
    ModelBundle,
    load_model,
    predict_event,
    predict_batch,
    get_model_metadata,
)


# ---------------------------------------------------------------------------
# Model bundle (loaded once at startup)
# ---------------------------------------------------------------------------

TRUST_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_DIR = TRUST_ROOT / "member4_ml" / "models"
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "perf_binary_model.joblib"
DEFAULT_PREPROCESSOR_PATH = DEFAULT_MODEL_DIR / "perf_binary_preprocessor.joblib"
DEFAULT_METADATA_PATH = DEFAULT_MODEL_DIR / "binary_model_metadata.json"


class ModelNotLoaded(RuntimeError):
    pass


_bundle: ModelBundle | None = None


def get_bundle() -> ModelBundle:
    global _bundle
    if _bundle is None:
        _bundle = load_model(
            model_path=DEFAULT_MODEL_PATH,
            preprocessor_path=DEFAULT_PREPROCESSOR_PATH,
            metadata_path=DEFAULT_METADATA_PATH,
        )
    return _bundle


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class EventIn(BaseModel):
    """A single normalized event dict (aligned with Member 3 events.jsonl).

    Required: event_id. All other fields optional — missing features are
    imputed by the fitted preprocessor.
    """

    event_id: str = Field(..., description="Unique event identifier")
    event_type: str | None = None
    event_time: str | None = None
    event_time_original: str | None = None
    timestamp_semantics: str | None = None
    severity: str | None = None
    description: str | None = None
    evidence_id: str | None = None
    evidence_status: str | None = None
    ingested_at: str | None = None
    is_synthetic: bool = False
    source_record_id: str | None = None
    source_system: str | None = None
    attributes: dict[str, Any] | None = None

    model_config = {"extra": "allow"}


class PredictOut(BaseModel):
    event_id: str
    entity_id: str
    prediction: str
    attack_category: str | None
    risk_score: int | None
    confidence: float | None
    top_features: list[dict[str, Any]]
    model_version: str
    explanation: list[str]
    evidence_status: str
    is_synthetic: bool
    limitations: list[str]
    graph_context: dict[str, Any]


class BatchIn(BaseModel):
    events: list[EventIn]


class BatchOut(BaseModel):
    results: list[PredictOut]


class HealthOut(BaseModel):
    status: str
    model_loaded: bool
    model_name: str | None
    model_version: str | None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="TRUSTRAIL AI — Member 4 Inference API",
    description="Binary intrusion-detection inference service for SOC triage.",
    version="1.0.0",
)


@app.on_event("startup")
def _load_model_on_startup() -> None:
    get_bundle()


@app.get("/health", response_model=HealthOut, tags=["service"])
def health() -> HealthOut:
    try:
        bundle = get_bundle()
        meta = get_model_metadata(bundle)
        return HealthOut(
            status="ok",
            model_loaded=True,
            model_name=meta.get("model_name"),
            model_version=meta.get("model_version"),
        )
    except Exception:
        return HealthOut(
            status="degraded",
            model_loaded=False,
            model_name=None,
            model_version=None,
        )


@app.get("/metadata", tags=["service"])
def metadata() -> dict[str, Any]:
    bundle = get_bundle()
    return get_model_metadata(bundle)


@app.post("/predict", response_model=PredictOut, tags=["inference"])
def predict(event: EventIn) -> PredictOut:
    bundle = get_bundle()
    event_dict = event.model_dump(exclude_unset=True)
    try:
        result = predict_event(bundle, event_dict)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PredictOut(**result)


@app.post("/predict-batch", response_model=BatchOut, tags=["inference"])
def predict_batch_endpoint(batch: BatchIn) -> BatchOut:
    bundle = get_bundle()
    events = [e.model_dump(exclude_unset=True) for e in batch.events]
    try:
        results = predict_batch(bundle, events)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return BatchOut(results=[PredictOut(**r) for r in results])


@app.get("/", tags=["service"])
def root() -> dict[str, str]:
    return {
        "service": "TRUSTRAIL AI Member 4 Inference API",
        "docs": "/docs",
        "health": "/health",
        "predict": "/predict",
    }
