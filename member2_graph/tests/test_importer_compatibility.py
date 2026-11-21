import json
import tempfile
import unittest
from pathlib import Path

from neo4j.exceptions import ServiceUnavailable

from importer import Importer, read_jsonl, validate_entity, validate_relationship
from validate import run_neo4j_validation, validate_fixture


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "data" / "graph_fixture"


class RecordingTransaction:
    def __init__(self):
        self.calls = []

    def run(self, query, **parameters):
        self.calls.append((query, parameters))

class UnavailableDriver:
    def session(self):
        raise ServiceUnavailable("simulated private connection details")


class ImporterCompatibilityTests(unittest.TestCase):
    def test_member3_fixture_matches_graph_contract(self):
        result = validate_fixture(FIXTURE)

        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["files"]["entities"], 18)
        self.assertEqual(result["files"]["events"], 17)
        self.assertEqual(result["files"]["evidence"], 17)
        self.assertEqual(result["relationships"]["domain_original_entity"], 17)
        self.assertEqual(result["relationships"]["supported_by"], 17)
        self.assertEqual(result["relationships"]["observed_on"], 34)

    def test_importer_writes_backend_compatible_labels_and_ids(self):
        importer = Importer(FIXTURE)
        transaction = RecordingTransaction()

        entities = read_jsonl(FIXTURE / "entities.jsonl")
        events = read_jsonl(FIXTURE / "events.jsonl")
        evidence = read_jsonl(FIXTURE / "evidence.jsonl")
        relationships = read_jsonl(FIXTURE / "relationships.jsonl")

        importer._write_entities_batch(transaction, [entities[0][1]])
        importer._write_events_batch(transaction, [events[0][1]])
        importer._write_evidence_batch(transaction, [evidence[0][1]])
        importer._write_relationships_batch(
            transaction,
            [relationships[0][1], relationships[17][1]],
        )

        entity_query, entity_params = transaction.calls[0]
        self.assertIn("GraphNode:Entity", entity_query)
        self.assertEqual(entity_params["eid"], "USR-001")
        self.assertEqual(entity_params["p_id"], "USR-001")

        event_query, event_params = transaction.calls[1]
        self.assertIn("GraphNode:SecurityEvent", event_query)
        self.assertIn("{id: $eid}", event_query)
        self.assertEqual(event_params["eid"], "EVT-001")
        self.assertEqual(event_params["p_id"], "EVT-001")
        self.assertEqual(event_params["p_source_entity_id"], "USR-001")

        evidence_query, evidence_params = transaction.calls[2]
        self.assertIn("GraphNode:Evidence", evidence_query)
        self.assertIn("{id: $eid}", evidence_query)
        self.assertEqual(evidence_params["eid"], "EVD-001")
        self.assertEqual(evidence_params["p_id"], "EVD-001")

        domain_query, _ = transaction.calls[3]
        self.assertIn("GraphNode:Entity", domain_query)
        supported_by_query, _ = transaction.calls[4]
        self.assertIn(
            "(s:GraphNode:SecurityEvent {event_id: $source_id})",
            supported_by_query,
        )
        self.assertIn(
            "(t:GraphNode:Evidence {evidence_id: $target_id})",
            supported_by_query,
        )
        self.assertIn("SUPPORTED_BY {relationship_id: $relationship_id}", supported_by_query)

    def test_importer_reports_malformed_and_missing_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_dir = Path(temp_dir)
            (fixture_dir / "entities.jsonl").write_text("{invalid json\n", encoding="utf-8")

            importer = Importer(fixture_dir)
            importer._validate_and_partition()
            result = validate_fixture(fixture_dir)

            self.assertTrue(importer.report.errors)
            self.assertTrue(any("invalid JSON" in error.reason for error in importer.report.errors))
            self.assertEqual(importer._events_valid, [])
            self.assertFalse(result["valid"])
            self.assertTrue(any("missing file" in error for error in result["errors"]))

    def test_duplicate_node_ids_are_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_dir = Path(temp_dir)
            entity = {"id": "DUP-001", "type": "Host", "synthetic": False}
            (fixture_dir / "entities.jsonl").write_text(
                json.dumps(entity) + "\n" + json.dumps(entity) + "\n",
                encoding="utf-8",
            )
            for name in ("events", "evidence", "relationships", "rejected"):
                (fixture_dir / f"{name}.jsonl").write_text("", encoding="utf-8")

            importer = Importer(fixture_dir)
            importer._validate_and_partition()
            result = validate_fixture(fixture_dir)

            self.assertEqual(importer._entities_valid, [])
            self.assertEqual(
                sum("duplicate graph node identifier" in error.reason
                    for error in importer.report.errors),
                2,
            )
            self.assertFalse(result["valid"])
            self.assertTrue(any("duplicate graph node identifier" in error
                                for error in result["errors"]))

    def test_invalid_identifiers_and_observed_on_roles_are_rejected(self):
        self.assertIn(
            "non-empty string",
            validate_entity({"id": " ", "type": "Host", "synthetic": False}),
        )
        observed_on = {
            "relationship_id": "REL-001",
            "source_id": "EVT-001",
            "target_id": "HOST-001",
            "relationship_type": "OBSERVED_ON",
            "evidence_status": "observed",
            "event_id": "EVT-001",
            "is_synthetic": False,
            "relationship_category": "event_trace",
            "endpoint_role": None,
        }
        self.assertIn("endpoint_role", validate_relationship(observed_on))

    def test_nonpositive_batch_size_is_rejected(self):
        for batch_size in (0, -1):
            with self.subTest(batch_size=batch_size):
                with self.assertRaises(ValueError):
                    Importer(FIXTURE, batch_size=batch_size)

    def test_live_validator_reports_connection_failure_without_raw_details(self):
        result = run_neo4j_validation(UnavailableDriver())

        self.assertFalse(result["queries_succeeded"])
        self.assertTrue(result["errors"])
        self.assertNotIn("simulated private connection details", str(result))


if __name__ == "__main__":
    unittest.main()
