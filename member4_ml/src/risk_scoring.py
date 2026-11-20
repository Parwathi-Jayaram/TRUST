"""Phase 9 — Transparent Investigation-Priority Risk Scoring (Member 4).

Develops a transparent, documented risk-scoring approach to help the SOC
prioritize investigation. The score is an *investigation priority*, not a
probability of compromise.

Inputs (each component documented with meaning, scale, source, limitations):
  1. Detection signal — model prediction (binary: normal/attack)
  2. Model confidence — max class probability (0-1)
  3. Event severity — supplied severity level (if available)
  4. Graph context — number of related suspicious events, critical assets
  5. Evidence recency — how recent the event is

Design:
  Investigation Priority = f(Detection Signal, Confidence, Severity,
                             Graph Context, Recency)

Each component is normalized to 0-100, weighted, and summed. Weights and
the formula are documented and fixed (not learned), so the score is fully
explainable and auditable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from datetime import datetime, timezone
import json


# Fixed, documented component weights. Sums to 1.0.
# These are heuristic weights chosen for investigation prioritization,
# not statistically validated probabilities.
WEIGHTS = {
    "detection_signal": 0.35,   # model prediction (attack vs normal)
    "confidence": 0.20,         # model confidence in the prediction
    "severity": 0.15,           # supplied event severity
    "graph_context": 0.20,      # related suspicious events + critical assets
    "recency": 0.10,            # how recent the event is
}


def _assert_weights_sum_to_one(weights: dict[str, float]) -> None:
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"Weights must sum to 1.0, got {total}")


_assert_weights_sum_to_one(WEIGHTS)


def _detection_signal_score(prediction: str | Any) -> float:
    """Component 1: Detection signal.

    Scale: 0-100. Attack/suspicious = 100, normal = 0.
    Source: ML model prediction output.
    Limitation: A prediction is a detection signal, not proof of compromise.
    """
    pred_str = str(prediction).lower()
    if pred_str in {"suspicious", "attack", "1", "true", "yes"}:
        return 100.0
    return 0.0


def _confidence_score(confidence: float | None) -> float:
    """Component 2: Model confidence.

    Scale: 0-100 (confidence * 100). None/missing = 0.
    Source: model.predict_proba max probability.
    Limitation: Predicted probability is not a calibrated real-world
    probability of compromise.
    """
    if confidence is None:
        return 0.0
    return float(max(0.0, min(100.0, confidence * 100.0)))


def _severity_score(severity: Any) -> float:
    """Component 3: Event severity.

    Scale: 0-100 based on supplied severity level.
    Mapping: critical=100, high=75, medium=50, low=25, none/unknown=0.
    Source: event.severity field (supplied by Member 3 normalization).
    Limitation: Severity is supplied at ingestion; not independently verified.
    """
    if severity is None:
        return 0.0
    s = str(severity).lower().strip()
    mapping = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0,
        "none": 0.0,
        "unknown": 0.0,
        "": 0.0,
    }
    return mapping.get(s, 0.0)


def _graph_context_score(
    related_suspicious_events: int = 0,
    critical_assets_exposed: int = 0,
    max_related_events: int = 10,
) -> float:
    """Component 4: Graph context.

    Scale: 0-100 based on number of related suspicious events (capped) and
    whether critical assets are potentially exposed.
    Source: Member 2 Neo4j graph (Phase 8 integration).
    Limitation: A graph path does not prove an attacker traversed it.
    Related events do not confirm coordinated activity.
    """
    events_component = min(related_suspicious_events, max_related_events) / max_related_events * 60.0
    assets_component = 40.0 if critical_assets_exposed > 0 else 0.0
    return float(min(100.0, events_component + assets_component))


def _recency_score(
    event_time: str | None,
    max_age_hours: int = 168,  # 7 days
) -> float:
    """Component 5: Evidence recency.

    Scale: 0-100. More recent = higher score. Events older than
    max_age_hours score 0.
    Source: event.event_time (ISO 8601).
    Limitation: Depends on reliable event timestamps; missing time = 0.
    """
    if event_time is None:
        return 0.0
    try:
        event_dt = datetime.fromisoformat(str(event_time).replace("Z", "+00:00"))
    except Exception:
        return 0.0
    now = datetime.now(timezone.utc)
    if event_dt.tzinfo is None:
        event_dt = event_dt.replace(tzinfo=timezone.utc)
    age_hours = (now - event_dt).total_seconds() / 3600.0
    if age_hours < 0:
        return 100.0  # future timestamp, treat as very recent
    if age_hours > max_age_hours:
        return 0.0
    return float(max(0.0, (1.0 - age_hours / max_age_hours) * 100.0))


def compute_investigation_priority(
    prediction: str | Any,
    confidence: float | None = None,
    severity: Any = None,
    related_suspicious_events: int = 0,
    critical_assets_exposed: int = 0,
    event_time: str | None = None,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Compute a transparent investigation-priority score (0-100).

    Returns the final score plus a breakdown of each component's weighted
    contribution, so a SOC analyst can see exactly why an event scored
    the way it did.

    The score is an *investigation priority*, not a probability of
    compromise. Document limitations accordingly.

    Parameters
    ----------
    prediction : str | Any
        Model prediction (e.g. "suspicious", "attack", "normal").
    confidence : float | None
        Model confidence (0-1).
    severity : any
        Supplied event severity.
    related_suspicious_events : int
        Number of related suspicious events from graph context.
    critical_assets_exposed : int
        Number of critical assets potentially exposed (from graph).
    event_time : str | None
        Event timestamp (ISO 8601).
    weights : dict | None
        Optional override of component weights (must sum to 1.0).

    Returns
    -------
    dict with keys:
      score (0-100), level (low/medium/high/critical),
      components (dict with each component's raw and weighted score),
      weights_used, limitations.
    """
    w = weights if weights is not None else WEIGHTS
    _assert_weights_sum_to_one(w)

    detection_raw = _detection_signal_score(prediction)
    confidence_raw = _confidence_score(confidence)
    severity_raw = _severity_score(severity)
    graph_raw = _graph_context_score(
        related_suspicious_events=related_suspicious_events,
        critical_assets_exposed=critical_assets_exposed,
    )
    recency_raw = _recency_score(event_time=event_time)

    components = {
        "detection_signal": {
            "raw": detection_raw,
            "weight": w["detection_signal"],
            "weighted": detection_raw * w["detection_signal"],
        },
        "confidence": {
            "raw": confidence_raw,
            "weight": w["confidence"],
            "weighted": confidence_raw * w["confidence"],
        },
        "severity": {
            "raw": severity_raw,
            "weight": w["severity"],
            "weighted": severity_raw * w["severity"],
        },
        "graph_context": {
            "raw": graph_raw,
            "weight": w["graph_context"],
            "weighted": graph_raw * w["graph_context"],
        },
        "recency": {
            "raw": recency_raw,
            "weight": w["recency"],
            "weighted": recency_raw * w["recency"],
        },
    }

    score = sum(c["weighted"] for c in components.values())
    score = float(max(0.0, min(100.0, score)))

    level = _score_to_level(score)

    return {
        "score": round(score, 2),
        "level": level,
        "components": components,
        "weights_used": w,
        "limitations": [
            "This is an investigation priority score, not a probability of compromise.",
            "Component weights are heuristic and documented, not statistically validated.",
            "Graph context is relationship evidence, not proof of attacker traversal.",
            "Model confidence is not a calibrated real-world probability.",
        ],
    }


def _score_to_level(score: float) -> str:
    """Map a 0-100 score to an investigation priority level."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def priority_to_recommendation(level: str) -> str:
    """Return a recommended next investigation step for a priority level."""
    recommendations = {
        "critical": "Immediate analyst review; escalate to senior SOC; consider graph blast-radius analysis.",
        "high": "Analyst review within the shift; correlate with related graph events.",
        "medium": "Standard triage queue; review during next analyst cycle.",
        "low": "Log for trend analysis; no immediate action required.",
    }
    return recommendations.get(level, "Review as time permits.")


def save_risk_methodology(path: str | Path) -> None:
    """Save the documented risk-scoring methodology to a markdown file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# TRUSTRAIL AI — Member 4 Investigation-Priority Risk Score",
        "",
        "## Overview",
        "",
        "The investigation-priority score helps the SOC prioritize which "
        "detected events to investigate first. It is a **heuristic score "
        "(0-100)**, not a probability of compromise. Every component, "
        "weight, and limitation is documented below so the score is "
        "fully explainable and auditable.",
        "",
        "## Formula",
        "",
        "Investigation Priority = Σ (component_score × component_weight)",
        "",
        "All components are normalized to a 0-100 scale before weighting.",
        "",
        "## Components and Weights",
        "",
        "| Component | Weight | Scale | Source | Limitation |",
        "|-----------|--------|-------|--------|------------|",
        "| Detection signal | 0.35 | 0-100 (attack=100, normal=0) | ML model prediction | Prediction is a detection signal, not proof of compromise |",
        "| Confidence | 0.20 | 0-100 (probability × 100) | model.predict_proba | Not a calibrated real-world probability |",
        "| Severity | 0.15 | 0-100 (critical=100 ... none=0) | Member 3 normalized event.severity | Supplied at ingestion, not independently verified |",
        "| Graph context | 0.20 | 0-100 (related events + critical assets) | Member 2 Neo4j graph | Path does not prove attacker traversal |",
        "| Recency | 0.10 | 0-100 (recent=100, >7 days=0) | Member 3 normalized event.event_time | Depends on reliable timestamps |",
        "",
        "## Score Levels",
        "",
        "| Level | Score Range | Recommended Action |",
        "|-------|-------------|--------------------|",
        "| Critical | 75-100 | Immediate analyst review; escalate; graph blast-radius analysis |",
        "| High | 50-74 | Analyst review within the shift; correlate with graph events |",
        "| Medium | 25-49 | Standard triage queue |",
        "| Low | 0-24 | Log for trend analysis; no immediate action |",
        "",
        "## Limitations",
        "",
        "- The score is an investigation priority, not a probability of compromise.",
        "- Component weights are heuristic and documented; they are not learned from data.",
        "- Graph context is relationship evidence, not proof that an attacker traversed a path.",
        "- Model confidence is not a calibrated real-world probability.",
        "- A high score does not automatically trigger containment; human analysts remain in control.",
        "",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 9 Risk Scoring — self-check")
    print("=" * 60)

    # Example 1: High-priority suspicious event.
    r1 = compute_investigation_priority(
        prediction="suspicious",
        confidence=0.9,
        severity="high",
        related_suspicious_events=3,
        critical_assets_exposed=1,
        event_time="2026-01-15T10:22:00Z",
    )
    print("\nExample 1 — Suspicious, high confidence, severe, recent, graph context:")
    print(f"  Score: {r1['score']} ({r1['level']})")
    print(f"  Recommendation: {priority_to_recommendation(r1['level'])}")
    for name, c in r1["components"].items():
        print(f"  {name}: raw={c['raw']:.1f}, weighted={c['weighted']:.2f}")

    # Example 2: Low-priority normal event.
    r2 = compute_investigation_priority(
        prediction="normal",
        confidence=0.95,
        severity="low",
        related_suspicious_events=0,
        critical_assets_exposed=0,
        event_time="2026-01-10T08:00:00Z",
    )
    print("\nExample 2 — Normal, high confidence, low severity, no graph context:")
    print(f"  Score: {r2['score']} ({r2['level']})")
    print(f"  Recommendation: {priority_to_recommendation(r2['level'])}")

    # Example 3: Missing confidence (should degrade gracefully).
    r3 = compute_investigation_priority(
        prediction="suspicious",
        confidence=None,
        severity=None,
        related_suspicious_events=0,
        critical_assets_exposed=0,
        event_time=None,
    )
    print("\nExample 3 — Suspicious but missing confidence/severity/time:")
    print(f"  Score: {r3['score']} ({r3['level']})")

    # Save methodology report.
    TRUST_ROOT = Path(__file__).resolve().parents[2]
    REPORT_DIR = TRUST_ROOT / "member4_ml" / "reports"
    save_risk_methodology(REPORT_DIR / "risk_scoring_methodology.md")
    print(f"\nSaved methodology: {REPORT_DIR / 'risk_scoring_methodology.md'}")
    print("\nRisk scoring self-check complete.")
