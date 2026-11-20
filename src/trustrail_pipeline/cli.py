"""Command-line entry point for the local data pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pipeline import run_pipeline
from .synthetic import write_demo_input


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize local defensive cybersecurity telemetry.")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="ingest one local CSV, JSON, or JSONL file")
    ingest.add_argument("--input", required=True, type=Path)
    ingest.add_argument("--output-dir", required=True, type=Path)
    ingest.add_argument("--dataset-id", required=True)
    ingest.add_argument("--source-system", required=True)
    ingest.add_argument("--version", default="unknown")
    ingest.add_argument("--source-url")
    ingest.add_argument("--license")
    ingest.add_argument(
        "--evidence-status",
        choices=("observed", "derived", "unconfirmed", "synthetic"),
        default="observed",
    )
    ingest.add_argument("--synthetic", action="store_true")
    ingest.add_argument("--format", choices=("csv", "json", "jsonl"))
    ingest.add_argument("--max-records", type=int)

    demo = commands.add_parser("demo", help="generate and process a deterministic synthetic example")
    demo.add_argument("--output-dir", required=True, type=Path)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "demo":
        input_path = write_demo_input(args.output_dir / "input" / "member3_demo.jsonl")
        report = run_pipeline(
            input_path,
            args.output_dir / "processed",
            dataset_id="trustrail-demo-v1",
            source_system="trustrail_synthetic_generator",
            source_version="1",
            license_name="project-generated",
            evidence_status="observed",
            is_synthetic=True,
        )
    else:
        report = run_pipeline(
            args.input,
            args.output_dir,
            dataset_id=args.dataset_id,
            source_system=args.source_system,
            source_version=args.version,
            source_url=args.source_url,
            license_name=args.license,
            evidence_status=args.evidence_status,
            is_synthetic=args.synthetic,
            input_format=args.format,
            max_records=args.max_records,
        )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
