import unittest
import tempfile
from pathlib import Path

from backend.app.services.member4_detection import (
    DetectionEngineUnavailable,
    DetectionInferenceError,
    Member4DetectionEngine,
)


class Member4DetectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_bundled_model_returns_prediction_and_separate_priority_score(self) -> None:
        event = {
            "event_id": "EVT-BACKEND-TEST",
            "event_type": "network_connection",
            "event_time": "2026-11-20T10:00:00Z",
            "severity": "medium",
            "evidence_status": "observed",
            "is_synthetic": True,
            "source_entity_id": "HOST-001",
            "source_system": "TRUSTRAIL_SYNTHETIC_SIMULATOR",
            "timestamp_semantics": "iso8601",
        }

        result = (await Member4DetectionEngine().predict_events([event]))[0]

        self.assertEqual(result["event_id"], event["event_id"])
        self.assertIn(result["prediction"], {"0", "1"})
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertGreaterEqual(result["confidence"], 0)
        self.assertLessEqual(result["confidence"], 1)
        self.assertIn(result["risk_level"], {"low", "medium", "high", "critical"})
        self.assertEqual(result["model_confidence_percent"], round(result["confidence"] * 100))

    async def test_nested_attributes_are_flattened_for_member4_model(self) -> None:
        engine = Member4DetectionEngine()
        engine._load()
        model_predict_batch = engine._predict_batch
        model_inputs = []

        def capture_inputs(bundle, events):
            model_inputs.extend(events)
            return model_predict_batch(bundle, events)

        engine._predict_batch = capture_inputs
        event = {
            "event_id": "EVT-FLOW-ATTRIBUTES",
            "event_type": "network_flow",
            "event_time": "2026-11-20T10:00:00Z",
            "is_synthetic": True,
            "attributes": {
                "Protocol": 6,
                "SrcPort": 53000,
                "DstPort": 443,
                "SrcBytes": 2048,
                "DstBytes": 8192,
                "Duration": 12,
            },
        }

        result = (await engine.predict_events([event]))[0]

        self.assertEqual(model_inputs[0]["attr_Protocol"], 6)
        self.assertEqual(model_inputs[0]["attr_DstPort"], 443)
        self.assertNotIn("attr_Protocol", event)
        self.assertEqual(result["event_id"], event["event_id"])

    async def test_malformed_attributes_return_inference_error(self) -> None:
        engine = Member4DetectionEngine()
        engine._bundle = object()

        with self.assertRaises(DetectionInferenceError):
            await engine.predict_events([{
                "event_id": "EVT-MALFORMED",
                "attributes": ["not", "an", "object"],
            }])

    async def test_missing_event_id_returns_inference_error(self) -> None:
        engine = Member4DetectionEngine()
        engine._bundle = object()

        with self.assertRaises(DetectionInferenceError):
            await engine.predict_events([{"event_type": "network_flow"}])

    async def test_missing_model_artifacts_return_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = Member4DetectionEngine(Path(directory))

            with self.assertRaises(DetectionEngineUnavailable):
                await engine.predict_events([{"event_id": "EVT-001"}])

    async def test_model_inference_failure_is_reported(self) -> None:
        engine = Member4DetectionEngine()
        engine._bundle = object()

        def fail_prediction(bundle, events):
            raise RuntimeError("internal model detail")

        engine._predict_batch = fail_prediction

        with self.assertRaisesRegex(DetectionInferenceError, "Member 4 inference failed"):
            await engine.predict_events([{"event_id": "EVT-001"}])
