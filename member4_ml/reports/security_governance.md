# TRUSTRAIL AI — Member 4 Security, Governance & Responsible Use (Phase 13)

TRUSTRAIL AI is a **defensive** cybersecurity investigation platform. The
Member 4 AI/ML detection layer follows these rules:

## 1. Data Use
- Use only public, synthetic, or explicitly authorized data.
- Do not access systems without permission.
- Do not perform unauthorized scanning or exploitation.
- Do not collect credentials or secrets.
- Do not train on confidential telemetry without authorization.

## 2. Data Handling
- Do not expose private event data in logs.
- Preserve data provenance (source, retrieval time, license, synthetic flag).
- Every synthetic record carries `is_synthetic: true`; never presented as real.
- Synthetic test outcomes are kept separate from public-dataset evaluation results.

## 3. Model Behavior
- The model must **not** automatically block a user, isolate a machine,
  delete files, or disable services.
- It can **recommend** investigation or containment for an authorized
  analyst to review.
- Human analysts remain in control of incident response.

## 4. Output Integrity
- Keep prediction output separate from verified incident status.
- An ML prediction is a **detection signal**, not proof of compromise.
- A graph path is a **relationship**, not evidence of attacker traversal.
- Do not display a precise-looking score without documenting how it was
  calculated (investigation priority score, not probability of compromise).
- Do not make unsupported statements about attacker identity or intent.
- Do not describe a feature as the cause of an attack merely because it
  influenced the model's prediction.

## 5. No Secrets
- Do not expose internal secrets, API keys, or credentials in model output,
  logs, or reports.
- Model metadata contains only model name, version, task, target, and
  feature names — no sensitive values.

## 6. Auditability
- Every prediction must be traceable to its input data (event_id preserved).
- Every graph-derived insight must be explainable.
- Every important claim must be supported by evidence.
- Model and preprocessing versions are kept together (ModelBundle).
- All metrics come from actual reproducible experiments — no fabricated results.

## 7. Dataset Licensing (UNSW-NB15)
- Free for academic research use; commercial use requires author agreement.
- Citation required (Moustafa & Slay, 2015; plus four additional papers).
- Download gated on Member 1 approval of academic-use terms.

## 8. Synthetic Data Policy
- Every synthetic record and relationship carries a Boolean synthetic flag.
- Synthetic origin is separate from evidence_status (observed/derived/unconfirmed).
- Do not merge synthetic and sourced records without preserving each record's origin.
- Do not invent public-data labels, indicators, causal links, or incident outcomes.

## 9. Responsible ML
- Class imbalance is addressed and documented (macro F1, not just accuracy).
- Target leakage is checked and prevented (identifiers and leakage fields excluded).
- Threshold selection is documented and based on validation data, not test data.
- Limitations are clearly stated for rare attack categories.
- No unsupported security or performance claims are made.
