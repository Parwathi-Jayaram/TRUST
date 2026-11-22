import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import threading
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from pypdf import PdfReader

from backend.app.config import Settings
from backend.app.database.demo_connection import SyntheticFixtureConnection
from backend.app.main import create_app
from backend.app.routes import investigation_reports
from backend.app.services.report_pdf_service import ReportPdfError, ReportPdfTooLarge


REPORT_TOKEN = "test-report-token"


def make_settings(token=REPORT_TOKEN):
    return Settings(
        neo4j_uri="",
        neo4j_username="",
        neo4j_password="",
        neo4j_database="neo4j",
        cors_origins=("http://127.0.0.1:5173",),
        max_graph_depth=4,
        api_bearer_token=token,
        demo_fallback=True,
    )


class FixedDetectionEngine:
    async def predict_events(self, events):
        return [
            {
                "prediction": "suspicious",
                "risk_score": 76.5,
                "risk_level": "high",
                "confidence": 0.91,
                "model_name": "test-model",
                "model_version": "test-version",
                "explanation": ["Test risk factor"],
                "limitations": ["Test model limitation"],
                "entity_id": event.get("source_entity_id"),
            }
            for event in events
        ]


class InvestigationReportRouteTests(unittest.TestCase):
    def setUp(self):
        self.report_token = f"test-report-token-{uuid4().hex}"
        self.settings = make_settings(self.report_token)
        self.database = SyntheticFixtureConnection(self.settings)
        self.app = create_app(
            self.settings,
            self.database,
            FixedDetectionEngine(),
        )
        self.client_context = TestClient(
            self.app,
            headers={
                "Authorization": f"Bearer {self.report_token}",
                "Origin": "http://127.0.0.1:5173",
            },
        )
        self.client = self.client_context.__enter__()
        relationship = self.database._original_relationships()[0]
        self.entity_ids = [relationship["source_id"], relationship["target_id"]]
        response = self.client.post("/api/investigations", json={
            "title": "Synthetic report verification",
            "alert_id": "EVT-001",
            "entity_ids": self.entity_ids,
        })
        self.assertEqual(response.status_code, 201)
        self.investigation_id = response.json()["data"]["id"]

    def tearDown(self):
        self.client_context.__exit__(None, None, None)

    def report(self, **kwargs):
        return self.client.post(
            f"/api/investigations/{self.investigation_id}/report",
            **kwargs,
        )

    def test_report_download_contains_snapshot_graph_and_sections(self):
        evidence_id = self.database.evidence[0]["evidence_id"]
        attached = self.client.post(
            f"/api/investigations/{self.investigation_id}/evidence",
            json={"evidence_id": evidence_id},
        )
        self.assertEqual(attached.status_code, 200)
        response = self.report()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertEqual(response.headers["x-report-status"], "partial")
        self.assertIn(
            "x-report-status",
            response.headers["access-control-expose-headers"].lower(),
        )
        self.assertEqual(response.headers["cache-control"], "no-store, private")
        self.assertIn(".pdf", response.headers["content-disposition"])
        self.assertTrue(response.content.startswith(b"%PDF-"))

        reader = PdfReader(BytesIO(response.content))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        self.assertIn("Cyber Threat Investigation Report", text)
        self.assertIn("Executive summary", text)
        self.assertIn("Risk assessment", text)
        self.assertIn("Threat intelligence", text)
        self.assertIn("No Member 3 threat-intelligence provider", text)
        self.assertIn("Neo4j graph investigation", text)
        self.assertIn("AI explanation", text)
        self.assertIn("No investigation-level AI summary provider", text)
        self.assertIn("Evidence and references", text)
        self.assertIn("Disclaimer", text)
        self.assertIn("Path 1", text)
        self.assertIn("Synthetic", text)
        self.assertIn("76.5", text)
        self.assertIn("test-model", text)
        self.assertIn(self.database._original_relationships()[0]["relationship_type"], text)
        self.assertIn(self.entity_ids[0], text)
        self.assertIn(self.entity_ids[1], text)
        self.assertIn(evidence_id, text)
        self.assertEqual(len(self.database.report_snapshots[self.investigation_id]), 1)

        audit = self.database.investigations[self.investigation_id]["audit_history"]
        report_audit = [json.loads(item) for item in audit]
        self.assertEqual(report_audit[-1]["action"], "report_generated")
        self.assertEqual(report_audit[-1]["actor"], "backend_api")

        evidence_report = self.report()
        evidence_text = "\n".join(
            page.extract_text() or ""
            for page in PdfReader(BytesIO(evidence_report.content)).pages
        )
        self.assertIn(evidence_id, evidence_text)
        self.assertEqual(len(self.database.report_snapshots[self.investigation_id]), 1)

    def test_repeated_download_reuses_snapshot_and_audits_each_generation(self):
        first = self.report()
        self.assertEqual(first.status_code, 200)

        self.database.investigations[self.investigation_id]["title"] = "Changed after capture"
        second = self.report()

        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(self.database.report_snapshots[self.investigation_id]), 1)
        self.assertEqual(
            len(self.database.investigations[self.investigation_id]["audit_history"]),
            3,
        )
        extracted = "\n".join(
            page.extract_text() or "" for page in PdfReader(BytesIO(second.content)).pages
        )
        self.assertIn("Synthetic report verification", extracted)
        self.assertNotIn("Changed after capture", extracted)

    def test_untrusted_text_is_escaped_and_secrets_are_redacted(self):
        secret = "report-secret-value"
        json_secret = "json-secret-value"
        self.database.investigations[self.investigation_id]["title"] = (
            f"<script>alert(1)</script> API_KEY={secret} "
            f'"client_secret":"{json_secret}" '
            f"Authorization: Bearer {self.report_token}"
        )

        response = self.report()

        self.assertEqual(response.status_code, 200)
        text = "\n".join(
            page.extract_text() or "" for page in PdfReader(BytesIO(response.content)).pages
        )
        self.assertIn("[REDACTED]", text)
        self.assertNotIn(secret, text)
        self.assertNotIn(json_secret, text)
        self.assertNotIn(self.report_token, text)

    def test_pdf_failures_are_safe_and_do_not_persist_first_snapshot(self):
        with patch.object(
            investigation_reports,
            "render_investigation_report",
            side_effect=ReportPdfError("internal detail"),
        ):
            failed = self.report()

        self.assertEqual(failed.status_code, 500)
        self.assertEqual(failed.json()["detail"], "Investigation report generation failed.")
        self.assertEqual(self.database.report_snapshots.get(self.investigation_id), None)
        self.assertEqual(len(self.database.investigations[self.investigation_id]["audit_history"]), 1)

        with patch.object(
            investigation_reports,
            "render_investigation_report",
            side_effect=ReportPdfTooLarge("internal size detail"),
        ):
            oversized = self.report()

        self.assertEqual(oversized.status_code, 413)
        self.assertEqual(
            oversized.json()["detail"],
            "Generated report exceeds the allowed size.",
        )
        self.assertEqual(self.database.report_snapshots.get(self.investigation_id), None)

    def test_authentication_validation_and_request_size_limits(self):
        endpoint = f"/api/investigations/{self.investigation_id}/report"
        unauthorized = self.client.post(endpoint, headers={"Authorization": "Bearer wrong"})
        invalid_id = self.client.post("/api/investigations/no/report")
        missing = self.client.post("/api/investigations/INV-MISSING/report")
        request_body = self.client.post(endpoint, content=b"{}")
        oversized = self.client.post(endpoint, content=b"x" * 1_025)

        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(invalid_id.status_code, 422)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(request_body.status_code, 400)
        self.assertEqual(oversized.status_code, 413)

    def test_report_rate_limit_returns_retry_after(self):
        with patch.object(investigation_reports, "REPORT_REQUESTS_PER_MINUTE", 1):
            first = self.report()
            second = self.report()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
        self.assertIn("retry-after", second.headers)

    def test_missing_bearer_configuration_disables_report_generation(self):
        settings = make_settings(token="")
        database = SyntheticFixtureConnection(settings)
        app = create_app(settings, database, FixedDetectionEngine())
        with TestClient(app) as client:
            response = client.post("/api/investigations/INV-MISSING/report")

        self.assertEqual(response.status_code, 503)
        self.assertIn("API_BEARER_TOKEN", response.json()["detail"])

    def test_concurrent_requests_for_one_investigation_reuse_one_snapshot(self):
        entered_renderer = threading.Event()
        second_registered = threading.Event()
        release_renderer = threading.Event()
        render_count = 0
        register_count = 0
        render_count_lock = threading.Lock()
        original_renderer = investigation_reports.render_investigation_report
        original_register = investigation_reports._register_report_lock

        def delayed_renderer(snapshot, generated_at):
            nonlocal render_count
            with render_count_lock:
                render_count += 1
                entered_renderer.set()
            if not release_renderer.wait(timeout=5):
                raise TimeoutError("Test renderer was not released.")
            return original_renderer(snapshot, generated_at)

        def observed_register(investigation_id):
            nonlocal register_count
            with render_count_lock:
                register_count += 1
                if register_count == 2:
                    second_registered.set()
            return original_register(investigation_id)

        with (
            patch.object(investigation_reports, "render_investigation_report", delayed_renderer),
            patch.object(investigation_reports, "_register_report_lock", observed_register),
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(self.report)
                self.assertTrue(entered_renderer.wait(timeout=2))
                second = executor.submit(self.report)
                self.assertTrue(second_registered.wait(timeout=2))
                release_renderer.set()
                first_response = first.result(timeout=5)
                second_response = second.result(timeout=5)

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(render_count, 2)
        self.assertEqual(len(self.database.report_snapshots[self.investigation_id]), 1)
        self.assertEqual(
            len(self.database.investigations[self.investigation_id]["audit_history"]),
            3,
        )


if __name__ == "__main__":
    unittest.main()
