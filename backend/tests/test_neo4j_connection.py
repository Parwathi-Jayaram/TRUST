import os
import socket
import unittest
from unittest.mock import AsyncMock, patch

from neo4j.exceptions import ServiceUnavailable

from backend.app.config import Settings, get_settings
from backend.app.database.neo4j_connection import Neo4jConnection, Neo4jConnectionError


class RecordingResult:
    def data(self):
        return [{"value": 1}]


class RecordingTransaction:
    def run(self, query, parameters=None):
        return RecordingResult()


class RecordingSession:
    def __init__(self):
        self.transaction_timeouts = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def execute_read(self, transaction_function):
        self.transaction_timeouts.append(transaction_function.timeout)
        return transaction_function(RecordingTransaction())

    def execute_write(self, transaction_function):
        self.transaction_timeouts.append(transaction_function.timeout)
        return transaction_function(RecordingTransaction())


class RecordingDriver:
    def __init__(self, session):
        self.neo4j_session = session

    def session(self, database):
        return self.neo4j_session


def make_settings(
    uri: str = "",
    username: str = "",
    password: str = "",
    query_timeout: float = 30.0,
) -> Settings:
    return Settings(
        neo4j_uri=uri,
        neo4j_username=username,
        neo4j_password=password,
        neo4j_database="neo4j",
        cors_origins=(),
        max_graph_depth=4,
        neo4j_query_timeout_seconds=query_timeout,
    )


class Neo4jConnectionTests(unittest.IsolatedAsyncioTestCase):
    def test_unconfigured_database_is_reported_without_driver(self) -> None:
        connection = Neo4jConnection(make_settings())

        self.assertIsNone(connection.driver)

    def test_partial_database_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(Neo4jConnectionError, "configuration is incomplete"):
            Neo4jConnection(make_settings(uri="neo4j+s://example.databases.neo4j.io"))


    async def test_health_reports_successful_database_check(self) -> None:
        with patch("backend.app.database.neo4j_connection.GraphDatabase.driver"):
            connection = Neo4jConnection(make_settings("neo4j+s://example.test", "neo4j", "secret"))

        connection.connect = AsyncMock()
        connection.execute_read = AsyncMock(return_value=[{"ok": 1}])

        self.assertEqual(await connection.health(), {
            "status": "healthy",
            "configured": True,
            "database": "neo4j",
            "connectivity": True,
        })


    async def test_health_reports_database_failure_without_exposing_credentials(self) -> None:
        with patch("backend.app.database.neo4j_connection.GraphDatabase.driver"):
            connection = Neo4jConnection(make_settings("neo4j+s://example.test", "neo4j", "secret"))

        connection.connect = AsyncMock(side_effect=Neo4jConnectionError("connection failed"))

        self.assertEqual(await connection.health(), {
            "status": "unhealthy",
            "configured": True,
            "database": "neo4j",
        })

    async def test_health_reports_dns_resolution_failure_as_unhealthy(self) -> None:
        dns_error = ValueError("Cannot resolve address")
        dns_error.__cause__ = socket.gaierror("Name or service not known")
        with patch("backend.app.database.neo4j_connection.GraphDatabase.driver") as driver_factory:
            driver_factory.return_value.verify_connectivity.side_effect = dns_error
            connection = Neo4jConnection(
                make_settings("neo4j+s://example.test", "neo4j", "secret")
            )

        self.assertEqual(await connection.health(), {
            "status": "unhealthy",
            "configured": True,
            "database": "neo4j",
        })

    async def test_health_reports_driver_unavailable_as_unhealthy(self) -> None:
        with patch("backend.app.database.neo4j_connection.GraphDatabase.driver") as driver_factory:
            driver_factory.return_value.verify_connectivity.side_effect = ServiceUnavailable(
                "Unable to retrieve routing information"
            )
            connection = Neo4jConnection(
                make_settings("neo4j+s://example.test", "neo4j", "secret")
            )

        self.assertEqual(await connection.health(), {
            "status": "unhealthy",
            "configured": True,
            "database": "neo4j",
        })

    async def test_read_and_write_transactions_use_configured_timeout(self) -> None:
        connection = Neo4jConnection(make_settings(query_timeout=17.0))
        recording_session = RecordingSession()
        connection.driver = RecordingDriver(recording_session)

        self.assertEqual(await connection.execute_read("RETURN 1 AS value"), [{"value": 1}])
        self.assertEqual(await connection.execute_write("RETURN 1 AS value"), [{"value": 1}])
        self.assertEqual(recording_session.transaction_timeouts, [17.0, 17.0])

    def test_query_timeout_configuration_is_bounded(self) -> None:
        for value in ("0", "121", "not-a-number"):
            with self.subTest(value=value), patch.dict(
                os.environ,
                {"NEO4J_QUERY_TIMEOUT_SECONDS": value},
            ):
                with self.assertRaises(ValueError):
                    get_settings()
