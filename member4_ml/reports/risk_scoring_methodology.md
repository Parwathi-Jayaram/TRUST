# TRUSTRAIL AI — Member 4 Investigation-Priority Risk Score

## Overview

The investigation-priority score helps the SOC prioritize which detected events to investigate first. It is a **heuristic score (0-100)**, not a probability of compromise. Every component, weight, and limitation is documented below so the score is fully explainable and auditable.

## Formula

Investigation Priority = Σ (component_score × component_weight)

All components are normalized to a 0-100 scale before weighting.

## Components and Weights

| Component | Weight | Scale | Source | Limitation |
|-----------|--------|-------|--------|------------|
| Detection signal | 0.35 | 0-100 (attack=100, normal=0) | ML model prediction | Prediction is a detection signal, not proof of compromise |
| Confidence | 0.20 | 0-100 (probability × 100) | model.predict_proba | Not a calibrated real-world probability |
| Severity | 0.15 | 0-100 (critical=100 ... none=0) | Member 3 normalized event.severity | Supplied at ingestion, not independently verified |
| Graph context | 0.20 | 0-100 (related events + critical assets) | Member 2 Neo4j graph | Path does not prove attacker traversal |
| Recency | 0.10 | 0-100 (recent=100, >7 days=0) | Member 3 normalized event.event_time | Depends on reliable timestamps |

## Score Levels

| Level | Score Range | Recommended Action |
|-------|-------------|--------------------|
| Critical | 75-100 | Immediate analyst review; escalate; graph blast-radius analysis |
| High | 50-74 | Analyst review within the shift; correlate with graph events |
| Medium | 25-49 | Standard triage queue |
| Low | 0-24 | Log for trend analysis; no immediate action |

## Limitations

- The score is an investigation priority, not a probability of compromise.
- Component weights are heuristic and documented; they are not learned from data.
- Graph context is relationship evidence, not proof that an attacker traversed a path.
- Model confidence is not a calibrated real-world probability.
- A high score does not automatically trigger containment; human analysts remain in control.
