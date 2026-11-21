import unittest
from dataclasses import replace

from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import create_app


class AuthDatabase:
    async def execute_read(self, query, parameters=None):
        return [{
            "total_monitored_entities": 0,
            "devices": 0,
            "users": 0,
            "servers": 0,
            "active_incidents": 0,
        }]

    async def health(self):
        return {"status": "healthy"}

    async def close(self):
        pass


def make_settings(
    token: str = "test-token",
    app_env: str = "development",
) -> Settings:
    return Settings(
        neo4j_uri="",
        neo4j_username="",
        neo4j_password="",
        neo4j_database="neo4j",
        cors_origins=("http://localhost:5173",),
        max_graph_depth=4,
        api_bearer_token=token,
        app_env=app_env,
    )


class ApiBearerAuthTests(unittest.TestCase):
    def setUp(self):
        self.client_context = TestClient(
            create_app(make_settings(), AuthDatabase())
        )
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)

    def test_api_routes_reject_missing_or_invalid_token(self):
        self.assertEqual(self.client.get("/api/dashboard/overview").status_code, 401)
        self.assertEqual(
            self.client.get(
                "/api/dashboard/overview",
                headers={"Authorization": "Bearer wrong-token"},
            ).status_code,
            401,
        )

    def test_valid_token_can_access_api_and_health_is_public(self):
        response = self.client.get(
            "/api/dashboard/overview",
            headers={"Authorization": "Bearer test-token"},
        )
        health = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(health.status_code, 200)

    def test_liveness_endpoint_is_public_for_host_health_checks(self):
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_cors_preflight_allows_authorization_header(self):
        response = self.client.options(
            "/api/dashboard/overview",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["access-control-allow-origin"],
            "http://localhost:5173",
        )

    def test_production_requires_a_bearer_token_and_hides_api_docs(self):
        settings = replace(make_settings(token="", app_env="production"))
        with self.assertRaisesRegex(RuntimeError, "API_BEARER_TOKEN"):
            create_app(settings, AuthDatabase())

        app = create_app(make_settings(app_env="production"), AuthDatabase())
        self.assertIsNone(app.docs_url)
        self.assertIsNone(app.openapi_url)
