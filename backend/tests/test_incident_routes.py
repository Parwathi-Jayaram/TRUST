import json
import unittest

from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import create_app


class IncidentDatabase:
    def __init__(self):
        self.incidents = {}
        self.event_ids = {"EVT-001"}
        self.closed = False

    async def execute_read(self, query, parameters=None):
        incident_id = (parameters or {}).get("incident_id")
        if "incident.status AS status" in query:
            incident = self.incidents.get(incident_id)
            return [{"status": incident.get("status")}] if incident else []
        if "RETURN properties(incident)" in query:
            if "SKIP $skip" in query:
                return [{"incident": incident} for incident in self.incidents.values()]
            incident = self.incidents.get(incident_id)
            return [{"incident": incident}] if incident else []
        return []

    async def execute_write(self, query, parameters=None):
        if "CREATE (incident:GraphNode:Entity)" in query:
            event_id = parameters["event_id"]
            if event_id is not None and event_id not in self.event_ids:
                return []
            incident = dict(parameters["properties"])
            self.incidents[incident["id"]] = incident
            return [{"incident": incident}]

        incident = self.incidents.get(parameters["incident_id"])
        if incident is None:
            return []
        if "incident.status = $new_status" in query:
            if (incident.get("status") or "UNSET") != parameters["expected_status"]:
                return []
            incident["status"] = parameters["new_status"]
        elif "incident.priority = $priority" in query:
            incident["priority"] = parameters["priority"]
        incident["updated_at"] = parameters["updated_at"]
        incident.setdefault("status_history", []).append(parameters["audit_entry"])
        return [{"incident": incident}]

    async def health(self):
        return {"status": "healthy"}

    async def close(self):
        self.closed = True


def make_settings() -> Settings:
    return Settings(
        neo4j_uri="",
        neo4j_username="",
        neo4j_password="",
        neo4j_database="neo4j",
        cors_origins=(),
        max_graph_depth=4,
    )


class IncidentRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = IncidentDatabase()
        self.client_context = TestClient(create_app(make_settings(), self.database))
        self.client = self.client_context.__enter__()

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)

    def test_create_update_and_timeline_are_audited(self) -> None:
        created = self.client.post("/api/incidents", json={
            "title": "Investigate suspicious activity",
            "event_id": "EVT-001",
            "priority": "high",
        })

        self.assertEqual(created.status_code, 201)
        incident = created.json()["data"]
        incident_id = incident["id"]
        self.assertEqual(incident["status"], "NEW")
        self.assertEqual(len(incident["status_history"]), 1)

        updated = self.client.patch(
            f"/api/incidents/{incident_id}/status",
            json={"status": "INVESTIGATING", "note": "Analyst review started."},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["data"]["status"], "INVESTIGATING")

        priority = self.client.patch(
            f"/api/incidents/{incident_id}/priority",
            json={"priority": "critical", "note": "Escalated for review."},
        )
        self.assertEqual(priority.status_code, 200)
        self.assertEqual(priority.json()["data"]["priority"], "critical")

        timeline = self.client.get(f"/api/incidents/{incident_id}/timeline")
        entries = timeline.json()["data"]["timeline"]
        self.assertEqual([entry["action"] for entry in entries], [
            "created",
            "status_changed",
            "priority_changed",
        ])
        self.assertEqual(entries[1]["note"], "Analyst review started.")
        stored_entries = self.database.incidents[incident_id]["status_history"]
        self.assertTrue(all(isinstance(json.loads(entry), dict) for entry in stored_entries))

    def test_invalid_status_transition_is_rejected(self) -> None:
        created = self.client.post("/api/incidents", json={
            "title": "Incident",
            "priority": "medium",
        })
        incident_id = created.json()["data"]["id"]

        response = self.client.patch(
            f"/api/incidents/{incident_id}/status",
            json={"status": "RESOLVED"},
        )

        self.assertEqual(response.status_code, 409)

    def test_existing_incident_without_status_must_be_explicitly_initialized(self) -> None:
        self.database.incidents["INC-LEGACY"] = {
            "id": "INC-LEGACY",
            "type": "Incident",
            "priority": "medium",
        }

        rejected = self.client.patch(
            "/api/incidents/INC-LEGACY/status",
            json={"status": "INVESTIGATING"},
        )
        initialized = self.client.patch(
            "/api/incidents/INC-LEGACY/status",
            json={"status": "NEW"},
        )

        self.assertEqual(rejected.status_code, 409)
        self.assertEqual(initialized.status_code, 200)

    def test_missing_related_event_and_missing_incident_return_404(self) -> None:
        create_response = self.client.post("/api/incidents", json={
            "title": "Missing event",
            "event_id": "EVT-MISSING",
            "priority": "low",
        })
        get_response = self.client.get("/api/incidents/INC-MISSING")

        self.assertEqual(create_response.status_code, 404)
        self.assertEqual(get_response.status_code, 404)

    def test_invalid_incident_status_value_returns_422(self) -> None:
        response = self.client.patch(
            "/api/incidents/INC-001/status",
            json={"status": "UNKNOWN"},
        )

        self.assertEqual(response.status_code, 422)
