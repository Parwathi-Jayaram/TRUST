from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustrail_pipeline.normalization import normalize_record, normalize_timestamp, SourceInfo
from trustrail_pipeline.pipeline import run_pipeline
from trustrail_pipeline.synthetic import write_demo_input


class TimestampTests(unittest.TestCase):
    def test_timezone_aware_timestamp_is_normalized_to_utc(self) -> None:
        normalized, original, semantics = normalize_timestamp("2026-01-15T11:20:30+01:00")
        self.assertEqual(normalized, "2026-01-15T10:20:30Z")
        self.assertEqual(original, "2026-01-15T11:20:30+01:00")
        self.assertEqual(semantics, "iso8601")

    def test_naive_timestamp_is_not_silently_assumed_utc(self) -> None:
        normalized, original, semantics = normalize_timestamp("2026-01-15T10:20:30")
        self.assertIsNone(normalized)
        self.assertEqual(original, "2026-01-15T10:20:30")
        self.assertEqual(semantics, "timezone_missing")

    def test_small_numeric_timestamp_is_preserved_as_unresolved(self) -> None:
        normalized, original, semantics = normalize_timestamp("2")
        self.assertIsNone(normalized)
        self.assertEqual(original, "2")
        self.assertEqual(semantics, "source_numeric_time_unresolved")


class NormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = SourceInfo(
            dataset_id="test-dataset",
            source_system="unit-test",
            evidence_status="observed",
            is_synthetic=True,
        )

    def test_network_flow_extracts_directional_candidate_relationship(self) -> None:
        result = normalize_record(
            {
                "RecordID": "flow-1",
                "Time": "2026-01-15T10:20:30Z",
                "SrcDevice": "host-a",
                "DstDevice": "host-b",
                "source_type": "host",
                "target_type": "server",
                "Protocol": 6,
            },
            source=self.source,
            source_record_id="flow-1",
            ingested_at="2026-01-15T10:21:00Z",
        )
        self.assertEqual(result.relationship["relationship_type"], "COMMUNICATES_WITH")
        self.assertEqual(result.relationship["source_id"], result.entities[0]["id"])
        self.assertEqual(result.relationship["target_id"], result.entities[1]["id"])
        self.assertTrue(result.event["is_synthetic"])
        self.assertEqual(len(result.entities), 2)

    def test_authentication_event_requires_user_and_host_for_relationship(self) -> None:
        result = normalize_record(
            {"EventID": 4624, "Time": "2026-01-15T10:20:30Z", "Computer": "host-a"},
            source=self.source,
            source_record_id="auth-1",
        )
        self.assertIsNone(result.relationship)
        self.assertTrue(result.warnings)

    def test_failed_authentication_does_not_create_success_relationship(self) -> None:
        result = normalize_record(
            {
                "EventID": 4625,
                "Time": "2026-01-15T10:20:30Z",
                "UserName": "user-a",
                "Computer": "host-a",
            },
            source=self.source,
            source_record_id="auth-failed",
        )
        self.assertEqual(result.event["event_type"], "authentication")
        self.assertIsNone(result.relationship)

    def test_unrecognized_record_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match"):
            normalize_record(
                {"foo": "bar", "Time": "2026-01-15T10:20:30Z"},
                source=self.source,
                source_record_id="unknown-1",
            )

    def test_missing_timestamp_is_preserved_and_flagged(self) -> None:
        result = normalize_record(
            {"SrcDevice": "host-a", "DstDevice": "host-b"},
            source=self.source,
            source_record_id="no-time",
        )
        self.assertIsNone(result.event["event_time"])
        self.assertIsNone(result.event["event_time_original"])
        self.assertTrue(result.warnings)

    def test_explicit_graph_ids_and_relationship_direction_are_preserved(self) -> None:
        result = normalize_record(
            {
                "event_id": "EVT-001",
                "evidence_id": "EVD-001",
                "relationship_id": "REL-001",
                "event_time": "2026-11-14T08:10:00Z",
                "event_type": "security_event",
                "relationship_type": "DEPENDS_ON",
                "source_id": "SRV-001",
                "source_type": "server",
                "source_name": "demo-server",
                "target_id": "APP-001",
                "target_type": "application",
                "target_name": "demo-app",
                "evidence_status": "unconfirmed",
                "is_synthetic": False,
            },
            source=self.source,
            source_record_id="EVT-001",
        )
        self.assertEqual(result.event["event_id"], "EVT-001")
        self.assertEqual(result.event["evidence_id"], "EVD-001")
        self.assertEqual(result.relationship["relationship_id"], "REL-001")
        self.assertEqual(result.relationship["source_id"], "SRV-001")
        self.assertEqual(result.relationship["target_id"], "APP-001")
        self.assertEqual(result.relationship["evidence_status"], "unconfirmed")
        self.assertFalse(result.relationship["is_synthetic"])
        self.assertFalse(result.event["is_synthetic"])
        self.assertEqual(
            [(entity["id"], entity["type"]) for entity in result.entities],
            [("SRV-001", "server"), ("APP-001", "application")],
        )
        self.assertTrue(all(not entity["synthetic"] for entity in result.entities))

    def test_explicit_relationship_with_invalid_endpoint_types_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported endpoint types"):
            normalize_record(
                {
                    "event_id": "EVT-002",
                    "event_time": "2026-11-14T08:10:00Z",
                    "relationship_type": "DEPENDS_ON",
                    "source_id": "HOST-001",
                    "source_type": "host",
                    "target_id": "APP-001",
                    "target_type": "application",
                },
                source=self.source,
                source_record_id="EVT-002",
            )


class PipelineTests(unittest.TestCase):
    def test_demo_pipeline_marks_all_records_synthetic_and_writes_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = write_demo_input(root / "input" / "demo.jsonl")
            output_path = root / "processed"
            report = run_pipeline(
                input_path,
                output_path,
                dataset_id="demo",
                source_system="test-generator",
                evidence_status="synthetic",
            )

            self.assertEqual(report["counts"]["records_read"], 6)
            self.assertEqual(report["counts"]["records_accepted"], 6)
            self.assertEqual(report["counts"]["records_rejected"], 0)
            self.assertTrue((output_path / "metadata.json").is_file())
            events = [json.loads(line) for line in (output_path / "events.jsonl").read_text().splitlines()]
            self.assertTrue(all(event["is_synthetic"] for event in events))

            relationships = [
                json.loads(line) for line in (output_path / "relationships.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                {item["relationship_type"] for item in relationships},
                {
                    "AUTHENTICATED_TO",
                    "RUNS",
                    "COMMUNICATES_WITH",
                    "DEPENDS_ON",
                    "HAS_VULNERABILITY",
                    "INVOLVES",
                    "SUPPORTED_BY",
                    "OBSERVED_ON",
                },
            )
            self.assertEqual(report["counts"]["domain_relationships"], 6)
            self.assertEqual(report["counts"]["traceability_relationships"], 18)
            auth_evidence_link = next(
                item
                for item in relationships
                if item["relationship_type"] == "SUPPORTED_BY"
                and item["event_id"] == "EVT-001"
            )
            self.assertEqual(
                (auth_evidence_link["source_id"], auth_evidence_link["target_id"]),
                ("EVT-001", "EVD-001"),
            )
            auth_entity_links = [
                item
                for item in relationships
                if item["relationship_type"] == "OBSERVED_ON"
                and item["event_id"] == "EVT-001"
            ]
            self.assertEqual(
                {item["target_id"] for item in auth_entity_links},
                {"USR-001", "HOST-001"},
            )

    def test_invalid_timestamp_is_exported_and_reported_for_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "input.jsonl"
            input_path.write_text(
                '{"RecordID":"flow-1","Time":"not-a-time",'
                '"SrcDevice":"host-a","DstDevice":"host-b"}\n',
                encoding="utf-8",
            )
            report = run_pipeline(
                input_path,
                root / "out",
                dataset_id="test",
                source_system="test",
            )
            event = json.loads((root / "out" / "events.jsonl").read_text().strip())
            rejected = json.loads((root / "out" / "rejected.jsonl").read_text().strip())

            self.assertEqual(report["counts"]["invalid_records"], 1)
            self.assertEqual(report["counts"]["records_accepted"], 1)
            self.assertEqual(event["event_time"], None)
            self.assertEqual(event["event_time_original"], "not-a-time")
            self.assertEqual(rejected["raw_timestamp"], "not-a-time")
            self.assertTrue(rejected["recoverable"])

    def test_malformed_jsonl_is_reported_without_hiding_valid_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "input.jsonl"
            input_path.write_text(
                '{"RecordID":"ok","EventID":4624,"Time":"2026-01-15T10:20:30Z",'
                '"UserName":"user-a","Computer":"host-a"}\n'
                '{"broken":\n',
                encoding="utf-8",
            )
            report = run_pipeline(
                input_path,
                root / "out",
                dataset_id="test",
                source_system="test",
            )
            self.assertEqual(report["counts"]["records_accepted"], 1)
            self.assertEqual(report["counts"]["records_rejected"], 1)
            rejected = json.loads((root / "out" / "rejected.jsonl").read_text().strip())
            self.assertIn("invalid JSON", rejected["reason"])

    def test_non_finite_json_value_is_rejected_as_a_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "input.jsonl"
            input_path.write_text('{"EventID":4624,"Time":NaN}\n', encoding="utf-8")
            report = run_pipeline(
                input_path,
                root / "out",
                dataset_id="test",
                source_system="test",
            )
            self.assertEqual(report["counts"]["records_rejected"], 1)
            rejected = json.loads((root / "out" / "rejected.jsonl").read_text().strip())
            self.assertIn("non-finite JSON", rejected["reason"])

    def test_csv_rows_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "input.csv"
            input_path.write_text(
                "RecordID,Time,SrcDevice,DstDevice,source_type,target_type,Protocol\n"
                "flow-1,2026-01-15T10:20:30Z,host-a,server-a,host,server,6\n",
                encoding="utf-8",
            )
            report = run_pipeline(
                input_path,
                root / "out",
                dataset_id="test",
                source_system="test",
            )
            self.assertEqual(report["counts"]["records_accepted"], 1)
            relationships = [
                json.loads(line)
                for line in (root / "out" / "relationships.jsonl").read_text().splitlines()
            ]
            domain_relationship = next(
                item for item in relationships
                if item["relationship_type"] == "COMMUNICATES_WITH"
            )
            self.assertEqual(domain_relationship["relationship_type"], "COMMUNICATES_WITH")

    def test_repeated_ingestion_has_stable_ids_and_replaces_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = write_demo_input(root / "demo.jsonl")
            output_path = root / "out"
            args = {
                "dataset_id": "demo",
                "source_system": "test-generator",
                "evidence_status": "synthetic",
            }
            run_pipeline(input_path, output_path, **args)
            first = [
                json.loads(line)["event_id"]
                for line in (output_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            run_pipeline(input_path, output_path, **args)
            second = [
                json.loads(line)["event_id"]
                for line in (output_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(first, second)

    def test_large_json_document_is_rejected_before_full_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "large.json"
            input_path.write_text(" " * (16 * 1024 * 1024 + 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "in-memory JSON limit"):
                run_pipeline(
                    input_path,
                    root / "out",
                    dataset_id="test",
                    source_system="test",
                )


if __name__ == "__main__":
    unittest.main()
