import unittest

from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.database.neo4j_connection import Neo4jConnectionError
from backend.app.main import create_app
from backend.app.services.member4_detection import (
    DetectionEngineUnavailable,
    DetectionInferenceError,
    Member4DetectionEngine,
)


class StubDetectionEngine:
    async def predict_events(self, events):
        predictions = []
        for event in events:
            suspicious = event["event_id"] == "EVT-001"
            predictions.append({
                "event_id": event["event_id"],
                "entity_id": event.get("source_entity_id"),
                "prediction": "1" if suspicious else "0",
                "attack_category": "1" if suspicious else "0",
                "risk_score": 82.5 if suspicious else 8.0,
                "risk_level": "high" if suspicious else "low",
                "confidence": 0.91 if suspicious else 0.96,
                "model_confidence_percent": 91 if suspicious else 96,
                "explanation": ["Synthetic test model signal."],
                "top_features": [],
                "recommended_investigation_steps": "Review with an analyst.",
                "investigation_priority": {
                    "score": 82.5 if suspicious else 8.0,
                    "level": "high" if suspicious else "low",
                },
                "evidence_status": "model_generated_signal",
                "limitations": ["Synthetic model test."],
            })
        return predictions


class FailingDetectionEngine:
    def __init__(self, error):
        self.error = error

    async def predict_events(self, events):
        raise self.error


class ThreatDatabase:
    def __init__(self):
        self.calls = []
        self.events = {
            "EVT-001": {
                "event_id": "EVT-001",
                "event_type": "network_connection",
                "event_time": "2026-11-20T10:00:00Z",
                "severity": "high",
                "evidence_id": "EVD-001",
                "evidence_status": "observed",
                "attributes": {
                    "Protocol": 6,
                    "SrcPort": 53000,
                    "DstPort": 443,
                    "SrcBytes": 2048,
                    "DstBytes": 8192,
                },
                "source_entity_id": "HOST-001",
                "is_synthetic": True,
            },
            "EVT-002": {
                "event_id": "EVT-002",
                "event_type": "authentication",
                "event_time": "2026-11-20T11:00:00Z",
                "severity": "low",
                "evidence_id": "EVD-002",
                "evidence_status": "observed",
                "source_entity_id": "HOST-002",
                "is_synthetic": True,
            },
        }

    async def execute_read(self, query, parameters=None):
        self.calls.append((query, parameters))
        if "SKIP $skip" in query:
            return [{"event": event} for event in self.events.values()]
        if "OBSERVED_ON" in query:
            return [{
                "labels": ["GraphNode", "Entity"],
                "properties": {"id": "HOST-001", "type": "Host"},
            }]
        if "SUPPORTED_BY" in query:
            return [{
                "evidence": {"evidence_id": "EVD-001", "event_id": "EVT-001"},
            }]
        threat_id = parameters["threat_id"]
        event = self.events.get(threat_id)
        return [{"event": event}] if event else []

    async def health(self):
        return {"status": "healthy"}

    async def close(self):
        pass


def make_settings() -> Settings:
    return Settings(
        neo4j_uri="",
        neo4j_username="",
        neo4j_password="",
        neo4j_database="neo4j",
        cors_origins=(),
        max_graph_depth=4,
    )


class ThreatRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = ThreatDatabase()
        self.client_context = TestClient(create_app(
            make_settings(),
            self.database,
            StubDetectionEngine(),
        ))
        self.client = self.client_context.__enter__()

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)

    def test_threat_list_uses_member4_inference_and_separates_scores(self) -> None:
        response = self.client.get("/api/threats")

        self.assertEqual(response.status_code, 200)
        threat = response.json()["data"]["threats"][0]
        self.assertEqual(threat["event_id"], "EVT-001")
        self.assertEqual(threat["risk_score"], 82.5)
        self.assertEqual(threat["model_confidence_percent"], 91)
        self.assertNotEqual(threat["risk_score"], threat["model_confidence_percent"])
        self.assertEqual(threat["evidence_id"], "EVD-001")
        self.assertEqual(threat["evidence_status"], "model_generated_signal")
        self.assertEqual(threat["source_evidence_status"], "observed")
        self.assertTrue(threat["is_synthetic"])

    def test_high_risk_list_filters_using_investigation_priority(self) -> None:
        response = self.client.get("/api/threats/high-risk")

        self.assertEqual(response.status_code, 200)
        threats = response.json()["data"]["threats"]
        self.assertEqual([threat["event_id"] for threat in threats], ["EVT-001"])

    def test_threat_details_and_evidence_use_graph_trace_links(self) -> None:
        details = self.client.get("/api/threats/EVT-001")
        evidence = self.client.get("/api/threats/evidence/EVT-001")
        entities = self.client.get("/api/threats/associated-entities/EVT-001")

        self.assertEqual(details.status_code, 200)
        self.assertEqual(evidence.json()["data"]["evidence"][0]["evidence_id"], "EVD-001")
        self.assertEqual(
            entities.json()["data"]["entities"][0]["properties"]["id"],
            "HOST-001",
        )

    def test_non_suspicious_event_is_not_returned_as_threat(self) -> None:
        response = self.client.get("/api/threats/EVT-002")

        self.assertEqual(response.status_code, 404)

    def test_missing_event_returns_not_found(self) -> None:
        response = self.client.get("/api/threats/EVT-MISSING")

        self.assertEqual(response.status_code, 404)

    def test_empty_event_page_returns_empty_success(self) -> None:
        self.database.events = {}

        response = self.client.get("/api/threats")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["threats"], [])

    def test_invalid_pagination_is_rejected(self) -> None:
        response = self.client.get("/api/threats?skip=-1")

        self.assertEqual(response.status_code, 422)

    def test_malformed_stored_event_returns_gateway_error(self) -> None:
        self.database.events = {
            "EVT-MALFORMED": {"event_type": "network_connection"},
        }

        response = self.client.get("/api/threats")

        self.assertEqual(response.status_code, 502)
        self.assertIn("event_id", response.json()["message"])

    def test_malformed_stored_attributes_return_gateway_error(self) -> None:
        self.database.events = {
            "EVT-MALFORMED": {
                "event_id": "EVT-MALFORMED",
                "attributes": ["not", "an", "object"],
            },
        }

        response = self.client.get("/api/threats")

        self.assertEqual(response.status_code, 502)
        self.assertIn("malformed attributes", response.json()["message"])

    def test_model_failures_return_explicit_service_errors(self) -> None:
        cases = (
            (DetectionEngineUnavailable("model unavailable"), 503),
            (DetectionInferenceError("inference failed"), 502),
        )
        for error, expected_status in cases:
            with self.subTest(error=type(error).__name__):
                app = create_app(
                    make_settings(),
                    self.database,
                    FailingDetectionEngine(error),
                )
                with TestClient(app) as client:
                    response = client.get("/api/threats")
                self.assertEqual(response.status_code, expected_status)

    def test_neo4j_query_failure_returns_service_unavailable(self) -> None:
        class FailingDatabase(ThreatDatabase):
            async def execute_read(self, query, parameters=None):
                raise Neo4jConnectionError("Database query failed.")

        app = create_app(
            make_settings(),
            FailingDatabase(),
            StubDetectionEngine(),
        )
        with TestClient(app) as client:
            response = client.get("/api/threats")

        self.assertEqual(response.status_code, 503)

    def test_bundled_model_is_callable_through_fastapi_service(self) -> None:
        engine = Member4DetectionEngine()
        app = create_app(make_settings(), self.database, engine)

        with TestClient(app) as client:
            response = client.get("/api/threats")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["data"]["source"],
            "member4_on_demand_inference",
        )
        self.assertIsNotNone(engine._bundle)
