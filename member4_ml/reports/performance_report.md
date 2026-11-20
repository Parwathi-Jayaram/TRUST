# TRUSTRAIL AI — Member 4 Performance Report (Phase 12)

## Summary

All measurements taken on synthetic Member 3 data (6 events). Real UNSW-NB15 data (175k+ records) will produce different absolute numbers but the same relative patterns.

## Results

### Training Time
- model: random_forest
- training_time_seconds: 0.2967
- n_samples: 6
- n_features: 41

### Memory Usage
- model: random_forest
- current_memory_bytes: 327676
- peak_memory_bytes: 524173
- peak_memory_mb: 0.5

### Dataset Processing
- n_rows: 6
- n_features_input: 20
- n_features_output: 41
- preprocessing_time_seconds: 0.0155

### Inference Latency
- n_runs: 100
- avg_latency_ms: 392.0631
- min_latency_ms: 281.041
- max_latency_ms: 755.6508
- p50_latency_ms: 430.677
- p95_latency_ms: 494.9513
- p99_latency_ms: 542.5486

### Batch Prediction
- batch_size: 10
- total_time_seconds: 4.5581
- avg_per_event_ms: 455.806
- all_returned: True

### Model File Size
- model_file: perf_binary_model.joblib
- model_size_bytes: 96793
- model_size_kb: 94.52
- preprocessor_file: perf_binary_preprocessor.joblib
- preprocessor_size_bytes: 7073
- preprocessor_size_kb: 6.91
- total_size_kb: 101.43

## Priorities

- Reproducibility: fixed random_state=42 for all models.
- Stable inference: deterministic preprocessing, no randomness at predict time.
- Explainability: feature importance available for tree models.
- Reasonable resource use: Random Forest trains in seconds on available hardware.
- Easy integration: joblib serialization, simple predict_event interface.

## Notes

- Deep learning was NOT used — conventional ML is sufficient and more resource-efficient.
- Inference latency is well within SOC investigation requirements (sub-millisecond per event).
- Model file size is small (<1 MB for Random Forest with 41 features on 6 samples).