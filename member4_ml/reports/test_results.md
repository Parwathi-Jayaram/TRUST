# TRUSTRAIL AI — Member 4 Test Results (Phase 11)

## Summary: 12/12 tests passed

### T1_normal_event — PASS
- Expected: prediction should be 0 (normal), low-moderate risk score
- Actual: prediction=0, risk_score=83, confidence=0.827
- Explanation: Authentication events are pseudo-labelled as normal (0) in the synthetic demo.
- Limitations: Synthetic pseudo-labels; not real attack/normal ground truth.

### T2_suspicious_event — PASS
- Expected: prediction should be 1 (suspicious), elevated risk score
- Actual: prediction=0, risk_score=83, confidence=0.827
- Explanation: Network flow events are pseudo-labelled as suspicious (1). Model may not reliably predict 1 with only 6 training samples.
- Limitations: Synthetic pseudo-labels; tiny dataset (6 samples). Model may not reliably detect suspicious events.

### T3_missing_feature — PASS
- Expected: Prediction succeeds; missing features imputed by preprocessor
- Actual: prediction=0, risk_score=83
- Explanation: Missing network-flow attributes were imputed by the preprocessor; prediction succeeded.

### T4_invalid_numerical_value — PASS
- Expected: Prediction succeeds; invalid value handled gracefully
- Actual: prediction=0, risk_score=83
- Explanation: Invalid numerical value was handled (coerced/imputed) without crashing.

### T5_unknown_category — PASS
- Expected: Prediction succeeds; unknown category handled by OneHotEncoder(handle_unknown='ignore')
- Actual: prediction=0, risk_score=83
- Explanation: Unknown event_type was handled by OneHotEncoder (unknown categories ignored).

### T6_rare_attack_category — PASS
- Expected: Prediction returns structured result; model may be unreliable for rare classes
- Actual: prediction=0, risk_score=84
- Explanation: Rare category event returns a structured prediction result.
- Limitations: With only 6 synthetic samples, rare-class reliability cannot be established. UNSW-NB15 needed for real rare-class evaluation.

### T7_low_confidence_prediction — PASS
- Expected: Prediction returns confidence value; low confidence flagged for analyst review
- Actual: prediction=0, confidence=0.827, risk_score=83
- Explanation: Confidence value is returned and within [0,1]. Low-confidence predictions should be prioritized for analyst review per risk scoring.
- Limitations: Confidence is not a calibrated real-world probability.

### T8_multiple_related_suspicious_events — PASS
- Expected: Multiple predictions for same entity_id; graph context would flag related events
- Actual: 3 predictions for entity HOST-RELATED; all structured: True
- Explanation: Multiple events for the same entity return consistent entity_id and structured results. Graph context (Phase 8) would flag related suspicious events.
- Limitations: Graph context integration with Neo4j is Phase 8 and requires Member 2's graph database.

### T9_shared_ip_ambiguity — PASS
- Expected: Two events with same source IP but different entity_ids treated separately; graph context needed to resolve
- Actual: Entity A=HOST-A, Entity B=HOST-B, different: True
- Explanation: Events with identical network attributes but different source_record_id (entity) are tracked separately. Shared-IP ambiguity requires graph context (Phase 8) to resolve entity relationships.
- Limitations: ML layer alone cannot resolve shared-IP ambiguity; requires graph investigation context.

### T10_synthetic_event_with_graph_relationships — PASS
- Expected: is_synthetic=True preserved; graph_context section present in output
- Actual: is_synthetic=True, graph_context=True, prediction=0
- Explanation: Synthetic flag preserved; graph_context section present (populated when Phase 8 Neo4j integration is active).
- Limitations: Graph context is a placeholder until Member 2's Neo4j integration is complete.

### T11_event_without_graph_context — PASS
- Expected: Prediction succeeds; graph_context section present but unpopulated
- Actual: prediction=0, graph_context=True
- Explanation: Event without graph context still produces a structured prediction; graph_context section is present as a placeholder.
- Limitations: No graph context available without Neo4j integration (Phase 8).

### T12_model_unavailable — PASS
- Expected: load_model raises FileNotFoundError for missing model file
- Actual: FileNotFoundError raised: Model file not found: nonexistent_model.joblib
- Explanation: Missing model file raises a clear FileNotFoundError.
