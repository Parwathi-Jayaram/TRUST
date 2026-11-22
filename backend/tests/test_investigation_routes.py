import json
import unittest

from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.database.demo_connection import SyntheticFixtureConnection
from backend.app.database.neo4j_connection import Neo4jConnectionError
from backend.app.main import create_app
from backend.app.services.member4_detection import DetectionInferenceError


class InvestigationDatabase:
    def __init__(self):
        self.investigations = {}
        self.event_ids = {"EVT-001"}
        self.events = {
            "EVT-001": {
                "event_id": "EVT-001",
                "event_type": "network_flow",
                "event_time": "2026-11-20T10:00:00Z",
                "severity": "medium",
                "description": "Observed test flow.",
                "evidence_id": "EVD-001",
                "evidence_status": "observed",
                "source_entity_id": "HOST-001",
                "is_synthetic": False,
            },
        }
        self.entity_ids = {"HOST-001", "HOST-002"}
        self.read_calls = []
        self.graph_paths = []
        self.graph_property_blob = {}
        self.report_snapshots = {}
        self.fail_reads = False
        self.evidence = {
            "EVD-001": {"evidence_id": "EVD-001", "event_id": "EVT-001"},
        }

    async def execute_read(self, query, parameters=None):
        parameters = parameters or {}
        if self.fail_reads:
            raise Neo4jConnectionError("Database query failed.")
        self.read_calls.append((query, parameters))
        investigation_id = parameters.get("investigation_id")
        if "properties(snapshot) AS report_snapshot" in query:
            snapshot = self.report_snapshots.get(parameters.get("report_id"))
            if (
                snapshot is None
                or snapshot.get("investigation_id") != investigation_id
            ):
                return []
            return [{"report_snapshot": snapshot}]
        if "evidence.evidence_id IN $evidence_ids" in query:
            return [
                {"evidence": self.evidence[evidence_id]}
                for evidence_id in parameters.get("evidence_ids", [])
                if evidence_id in self.evidence
            ][:parameters["limit"]]
        if "event_id: $threat_id" in query:
            event = self.events.get(parameters.get("threat_id"))
            return [{"event": event}] if event else []
        if "source_labels" in query and "OPTIONAL MATCH path =" in query:
            entity_id = parameters["entity_id"]
            if entity_id not in self.entity_ids:
                return []
            return [{
                "source_labels": ["GraphNode", "Entity"],
                "source_properties": {
                    "id": entity_id,
                    "is_synthetic": False,
                    **self.graph_property_blob,
                },
                "nodes": [{
                    "id": entity_id,
                    "labels": ["GraphNode", "Entity"],
                    "properties": {
                        "id": entity_id,
                        "is_synthetic": False,
                        **self.graph_property_blob,
                    },
                }],
                "relationships": [],
            }]
        if "MATCH path =" in query:
            return self.graph_paths
        if "investigation.status AS status" in query:
            investigation = self.investigations.get(investigation_id)
            return [{"status": investigation["status"]}] if investigation else []
        if "properties(evidence) AS evidence" in query:
            investigation = self.investigations.get(investigation_id)
            if not investigation:
                return []
            return [
                {"evidence": self.evidence[evidence_id]}
                for evidence_id in investigation["evidence_ids"]
            ]
        if "properties(investigation)" in query:
            if "SKIP $skip" in query:
                return [
                    {"investigation": investigation}
                    for investigation in self.investigations.values()
                ]
            investigation = self.investigations.get(investigation_id)
            return [{"investigation": investigation}] if investigation else []
        return []

    async def execute_write(self, query, parameters=None):
        parameters = parameters or {}
        if "CREATE (snapshot:ReportSnapshot" in query:
            if parameters["investigation_id"] not in self.investigations:
                return []
            snapshot = {
                "id": parameters["report_id"],
                "investigation_id": parameters["investigation_id"],
                "payload_json": parameters["payload_json"],
                "schema_version": parameters["schema_version"],
                "snapshot_captured_at": parameters["snapshot_captured_at"],
            }
            self.report_snapshots[snapshot["id"]] = snapshot
            return [{"report_snapshot": snapshot}]
        if "CREATE (investigation:GraphNode:Entity)" in query:
            if parameters["alert_id"] not in (None, *self.event_ids):
                return []
            if any(entity_id not in self.entity_ids for entity_id in parameters["entity_ids"]):
                return []
            investigation = dict(parameters["properties"])
            self.investigations[investigation["id"]] = investigation
            return [{"investigation": investigation}]

        investigation = self.investigations.get(parameters["investigation_id"])
        if investigation is None:
            return []
        if "investigation.notes =" in query:
            investigation["notes"].append(parameters["note_entry"])
            investigation["audit_history"].append(parameters["audit_entry"])
            investigation["updated_at"] = parameters["updated_at"]
        elif "investigation.evidence_ids =" in query:
            evidence_id = parameters["evidence_id"]
            if evidence_id not in self.evidence:
                return []
            already_attached = evidence_id in investigation["evidence_ids"]
            if not already_attached:
                investigation["evidence_ids"].append(evidence_id)
                investigation["audit_history"].append(parameters["audit_entry"])
                investigation["updated_at"] = parameters["updated_at"]
            return [{
                "investigation": investigation,
                "already_attached": already_attached,
            }]
        elif "investigation.status = $new_status" in query:
            if investigation["status"] != parameters["expected_status"]:
                return []
            investigation["status"] = parameters["new_status"]
            investigation["audit_history"].append(parameters["audit_entry"])
            investigation["updated_at"] = parameters["updated_at"]
        return [{"investigation": investigation}]

    async def health(self):
        return {"status": "healthy"}

    async def close(self):
        pass


def make_settings():
    return Settings(
        neo4j_uri="",
        neo4j_username="",
        neo4j_password="",
        neo4j_database="neo4j",
        cors_origins=(),
        max_graph_depth=4,
    )


class InvestigationRouteTests(unittest.TestCase):
    def setUp(self):
        self.database = InvestigationDatabase()
        self.detection_engine = SnapshotDetectionEngine()
        self.client_context = TestClient(create_app(
            make_settings(),
            self.database,
            self.detection_engine,
        ))
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)

    def create_investigation(self):
        return self.client.post("/api/investigations", json={
            "title": "Investigate suspicious activity",
            "alert_id": "EVT-001",
            "entity_ids": ["HOST-001", "HOST-002"],
        })

    def test_investigation_attack_paths_reuse_graph_query(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        self.database.graph_paths = [{
            "nodes": [
                {
                    "id": "HOST-001",
                    "labels": ["GraphNode", "Entity"],
                    "properties": {"id": "HOST-001", "type": "Host"},
                },
                {
                    "id": "HOST-002",
                    "labels": ["GraphNode", "Entity"],
                    "properties": {"id": "HOST-002", "type": "Server"},
                },
            ],
            "relationships": [{
                "id": "REL-001",
                "type": "COMMUNICATES_WITH",
                "source_id": "HOST-001",
                "target_id": "HOST-002",
                "properties": {"relationship_category": "original_entity"},
            }],
            "depth": 1,
        }]

        response = self.client.get(
            f"/api/investigations/{investigation_id}/attack-paths",
            params={
                "source_id": "HOST-001",
                "target_id": "HOST-002",
                "depth": 2,
                "limit": 5,
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertEqual(data["investigation_id"], investigation_id)
        self.assertEqual(data["total_paths"], 1)
        self.assertIn("not proof", data["interpretation"])
        graph_query, graph_parameters = self.database.read_calls[-1]
        self.assertIn("MATCH path =", graph_query)
        self.assertEqual(graph_parameters, {
            "source_id": "HOST-001",
            "target_id": "HOST-002",
            "limit": 5,
        })

    def test_investigation_attack_paths_reject_unlinked_endpoints(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]

        response = self.client.get(
            f"/api/investigations/{investigation_id}/attack-paths",
            params={"source_id": "HOST-001", "target_id": "HOST-003"},
        )
        same_endpoint_response = self.client.get(
            f"/api/investigations/{investigation_id}/attack-paths",
            params={"source_id": "HOST-001", "target_id": "HOST-001"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(same_endpoint_response.status_code, 422)
        self.assertFalse(any("MATCH path =" in query for query, _ in self.database.read_calls))

    def test_create_add_notes_attach_evidence_and_read_timeline(self):
        created = self.create_investigation()

        self.assertEqual(created.status_code, 201)
        investigation = created.json()["data"]
        investigation_id = investigation["id"]
        self.assertEqual(investigation["status"], "OPEN")

        note_response = self.client.post(
            f"/api/investigations/{investigation_id}/notes",
            json={"content": "Reviewed source event."},
        )
        self.assertEqual(note_response.status_code, 200)

        evidence_response = self.client.post(
            f"/api/investigations/{investigation_id}/evidence",
            json={"evidence_id": "EVD-001"},
        )
        self.assertEqual(evidence_response.status_code, 200)

        evidence = self.client.get(
            f"/api/investigations/{investigation_id}/evidence"
        )
        self.assertEqual(evidence.json()["data"]["evidence"][0]["evidence_id"], "EVD-001")

        status_response = self.client.patch(
            f"/api/investigations/{investigation_id}/status",
            json={"status": "IN_PROGRESS", "note": "Triage started."},
        )
        self.assertEqual(status_response.status_code, 200)

        detail = self.client.get(f"/api/investigations/{investigation_id}")
        data = detail.json()["data"]
        self.assertEqual(data["notes"][0]["content"], "Reviewed source event.")
        self.assertEqual(data["status"], "IN_PROGRESS")
        self.assertEqual(len(data["audit_history"]), 4)

        timeline = self.client.get(
            f"/api/investigations/{investigation_id}/timeline"
        )
        self.assertEqual(len(timeline.json()["data"]["timeline"]), 4)
        persisted_history = self.database.investigations[investigation_id]["audit_history"]
        self.assertTrue(all(isinstance(json.loads(entry), dict) for entry in persisted_history))

    def test_missing_references_and_invalid_status_transitions_are_rejected(self):
        missing_reference = self.client.post("/api/investigations", json={
            "title": "Missing alert",
            "alert_id": "EVT-MISSING",
        })
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        invalid_transition = self.client.patch(
            f"/api/investigations/{investigation_id}/status",
            json={"status": "OPEN"},
        )

        self.assertEqual(missing_reference.status_code, 404)
        self.assertEqual(invalid_transition.status_code, 409)

    def test_duplicate_evidence_attachment_is_idempotent(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        endpoint = f"/api/investigations/{investigation_id}/evidence"

        first = self.client.post(endpoint, json={"evidence_id": "EVD-001"})
        history_count = len(first.json()["data"]["audit_history"])
        second = self.client.post(endpoint, json={"evidence_id": "EVD-001"})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(second.json()["data"]["audit_history"]), history_count)

    def test_report_snapshot_preserves_model_and_source_evidence_statuses(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        self.client.post(
            f"/api/investigations/{investigation_id}/evidence",
            json={"evidence_id": "EVD-001"},
        )

        response = self.client.post(
            f"/api/investigations/{investigation_id}/report-snapshots"
        )

        self.assertEqual(response.status_code, 201)
        snapshot = response.json()["data"]
        finding = snapshot["findings"][0]
        self.assertEqual(finding["event_id"], "EVT-001")
        self.assertEqual(finding["source_evidence_status"], "observed")
        self.assertEqual(finding["model_generated_signal"], "model_generated_signal")
        self.assertEqual(finding["prediction"], "1")
        self.assertEqual(snapshot["risk_assessment"]["score_kind"], "member4_investigation_priority")
        self.assertEqual(snapshot["threat_intelligence"]["status"], "not_implemented")
        self.assertEqual(snapshot["ai_explanation"]["status"], "not_implemented")
        self.assertTrue(snapshot["partial"])

        self.database.investigations[investigation_id]["title"] = "Changed after capture"
        retrieved = self.client.get(
            f"/api/investigations/{investigation_id}/report-snapshots/{snapshot['report_id']}"
        )
        self.assertEqual(retrieved.status_code, 200)
        self.assertEqual(retrieved.json()["data"], snapshot)
        self.assertNotEqual(
            retrieved.json()["data"]["investigation"]["title"],
            "Changed after capture",
        )

    def test_report_snapshot_survives_member4_failure_as_partial(self):
        self.detection_engine.failure = DetectionInferenceError(
            "Member 4 inference failed."
        )
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]

        response = self.client.post(
            f"/api/investigations/{investigation_id}/report-snapshots"
        )

        self.assertEqual(response.status_code, 201)
        snapshot = response.json()["data"]
        self.assertEqual(snapshot["risk_assessment"]["status"], "unavailable")
        self.assertIsNone(snapshot["risk_assessment"]["score"])
        self.assertEqual(snapshot["findings"], [])
        self.assertTrue(snapshot["partial"])

    def test_report_snapshot_does_not_assign_a_score_when_event_is_missing(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        self.database.events.pop("EVT-001")

        response = self.client.post(
            f"/api/investigations/{investigation_id}/report-snapshots"
        )

        self.assertEqual(response.status_code, 201)
        snapshot = response.json()["data"]
        self.assertEqual(
            snapshot["risk_assessment"]["status"],
            "insufficient_evidence",
        )
        self.assertIsNone(snapshot["risk_assessment"]["score"])
        self.assertEqual(snapshot["findings"], [])

    def test_report_snapshot_bounds_long_evidence_text_and_records_limitation(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        self.database.evidence["EVD-001"]["description"] = "x" * 5_000
        self.client.post(
            f"/api/investigations/{investigation_id}/evidence",
            json={"evidence_id": "EVD-001"},
        )

        response = self.client.post(
            f"/api/investigations/{investigation_id}/report-snapshots"
        )

        self.assertEqual(response.status_code, 201)
        snapshot = response.json()["data"]
        description = snapshot["evidence"][0]["description"]
        self.assertEqual(len(description), 4_000)
        self.assertIn("truncated", " ".join(snapshot["limitations"]))

    def test_report_snapshot_rejects_serialized_payload_over_one_megabyte(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        self.database.graph_property_blob = {
            f"property_{index}": "x" * 4_001
            for index in range(80)
        }

        response = self.client.post(
            f"/api/investigations/{investigation_id}/report-snapshots"
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.database.report_snapshots, {})

    def test_report_snapshot_missing_and_database_failure_are_explicit(self):
        missing = self.client.post(
            "/api/investigations/INV-MISSING/report-snapshots"
        )
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        self.database.fail_reads = True
        unavailable = self.client.post(
            f"/api/investigations/{investigation_id}/report-snapshots"
        )

        self.assertEqual(missing.status_code, 404)
        self.assertEqual(unavailable.status_code, 503)

    def test_report_snapshot_rejects_malformed_stored_payload(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        self.database.report_snapshots["RPT-BAD"] = {
            "id": "RPT-BAD",
            "investigation_id": investigation_id,
            "payload_json": "{not-json",
        }

        response = self.client.get(
            f"/api/investigations/{investigation_id}/report-snapshots/RPT-BAD"
        )

        self.assertEqual(response.status_code, 502)

    def test_synthetic_demo_connection_stores_and_retrieves_snapshots(self):
        database = SyntheticFixtureConnection(make_settings())
        client_context = TestClient(create_app(
            make_settings(),
            database,
            SnapshotDetectionEngine(),
        ))
        with client_context as client:
            created = client.post("/api/investigations", json={
                "title": "Synthetic report test",
                "alert_id": "EVT-001",
                "entity_ids": ["USR-001", "HOST-001"],
            })
            investigation_id = created.json()["data"]["id"]
            snapshot_response = client.post(
                f"/api/investigations/{investigation_id}/report-snapshots"
            )
            snapshot = snapshot_response.json()["data"]
            retrieved = client.get(
                f"/api/investigations/{investigation_id}/report-snapshots/"
                f"{snapshot['report_id']}"
            )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(snapshot_response.status_code, 201)
        self.assertTrue(snapshot["provenance"]["is_synthetic"])
        self.assertEqual(retrieved.status_code, 200)
        self.assertEqual(retrieved.json()["data"], snapshot)

    def test_report_snapshot_rejects_malformed_source_event(self):
        created = self.create_investigation()
        investigation_id = created.json()["data"]["id"]
        self.database.events["EVT-001"] = {"description": "missing event id"}

        response = self.client.post(
            f"/api/investigations/{investigation_id}/report-snapshots"
        )

        self.assertEqual(response.status_code, 502)


class SnapshotDetectionEngine:
    def __init__(self):
        self.failure = None

    async def predict_events(self, events):
        if self.failure:
            raise self.failure
        return [{
            "event_id": event["event_id"],
            "prediction": "1",
            "model_name": "test-model",
            "model_version": "test-version",
            "confidence": 0.9,
            "risk_score": 72,
            "risk_level": "high",
            "evidence_status": "model_generated_signal",
            "limitations": [],
        } for event in events]
