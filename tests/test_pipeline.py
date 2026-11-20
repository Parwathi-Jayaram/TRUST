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
            evidence_status="synthetic",
        )

    def test_network_flow_extracts_directional_candidate_relationship(self) -> None:
        result = normalize_record(
            {
                "RecordID": "flow-1",
                "Time": "2026-01-15T10:20:30Z",
                "SrcDevice": "host-a",
                "DstDevice": "host-b",
                "Protocol": 6,
            },
            source=self.source,
            source_record_id="flow-1",
            ingested_at="2026-01-15T10:21:00Z",
        )
        self.assertEqual(result.event["relationship"], "COMMUNICATES_WITH")
        self.assertEqual(result.event["source_entity_id"], result.relationship["source_entity_id"])
        self.assertEqual(result.event["target_entity_id"], result.relationship["target_entity_id"])
        self.assertEqual(result.event["evidence_status"], "synthetic")
        self.assertEqual(len(result.entities), 2)

    def test_authentication_event_requires_user_and_host_for_relationship(self) -> None:
        result = normalize_record(
            {"EventID": 4624, "Time": "2026-01-15T10:20:30Z", "Computer": "host-a"},
            source=self.source,
            source_record_id="auth-1",
        )
        self.assertIsNone(result.relationship)
        self.assertIsNone(result.event["relationship"])
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

    def test_missing_timestamp_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "timestamp"):
            normalize_record(
                {"SrcDevice": "host-a", "DstDevice": "host-b"},
                source=self.source,
                source_record_id="no-time",
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

            self.assertEqual(report["counts"]["records_read"], 3)
            self.assertEqual(report["counts"]["records_accepted"], 3)
            self.assertEqual(report["counts"]["records_rejected"], 0)
            self.assertTrue((output_path / "report.json").is_file())
            events = [json.loads(line) for line in (output_path / "events.jsonl").read_text().splitlines()]
            self.assertTrue(all(event["evidence_status"] == "synthetic" for event in events))

            relationships = [
                json.loads(line) for line in (output_path / "relationships.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                {item["relationship"] for item in relationships},
                {"AUTHENTICATED_TO", "RUNS", "COMMUNICATES_WITH"},
            )

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
                "RecordID,Time,SrcDevice,DstDevice,Protocol\n"
                "flow-1,2026-01-15T10:20:30Z,host-a,host-b,6\n",
                encoding="utf-8",
            )
            report = run_pipeline(
                input_path,
                root / "out",
                dataset_id="test",
                source_system="test",
            )
            self.assertEqual(report["counts"]["records_accepted"], 1)
            relationship = json.loads((root / "out" / "relationships.jsonl").read_text().strip())
            self.assertEqual(relationship["relationship"], "COMMUNICATES_WITH")

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
