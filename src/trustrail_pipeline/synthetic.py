"""Deterministic, explicitly synthetic input for safe local demonstrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEMO_RECORDS: tuple[dict[str, Any], ...] = (
    {
        "RecordID": "demo-auth-001",
        "event_id": "EVT-001",
        "evidence_id": "EVD-001",
        "relationship_id": "REL-001",
        "event_time": "2026-01-15T10:20:30Z",
        "event_type": "authentication",
        "description": "Synthetic successful authentication",
        "relationship_type": "AUTHENTICATED_TO",
        "source_id": "USR-001",
        "source_type": "user",
        "source_name": "alex.morgan",
        "source_criticality": "medium",
        "target_id": "HOST-001",
        "target_type": "host",
        "target_name": "demo-endpoint-01",
        "evidence_status": "observed",
        "is_synthetic": True,
    },
    {
        "RecordID": "demo-process-001",
        "EventID": 4688,
        "Time": "2026-01-15T10:21:00Z",
        "UserName": "demo-user-01",
        "Computer": "demo-endpoint-01",
        "ProcessName": "demo-client",
        "ProcessID": "4100",
        "ParentProcessName": "demo-shell",
    },
    {
        "RecordID": "demo-flow-001",
        "Time": "2026-01-15T10:22:00Z",
        "SrcDevice": "demo-endpoint-01",
        "DstDevice": "demo-app-server-01",
        "source_type": "host",
        "target_type": "server",
        "Protocol": 6,
        "SrcPort": 53000,
        "DstPort": 443,
        "Duration": 12,
        "SrcPackets": 14,
        "DstPackets": 11,
        "SrcBytes": 2048,
        "DstBytes": 8192,
    },
    {
        "RecordID": "demo-dependency-004",
        "event_id": "EVT-004",
        "evidence_id": "EVD-004",
        "relationship_id": "REL-004",
        "event_time": "2026-01-15T10:23:00Z",
        "event_type": "dependency_observation",
        "description": "Synthetic server-to-application dependency",
        "relationship_type": "DEPENDS_ON",
        "source_id": "SRV-001",
        "source_type": "server",
        "source_name": "demo-server",
        "target_id": "APP-001",
        "target_type": "application",
        "target_name": "demo-application",
        "evidence_status": "observed",
        "is_synthetic": True,
    },
    {
        "RecordID": "demo-vulnerability-005",
        "event_id": "EVT-005",
        "evidence_id": "EVD-005",
        "relationship_id": "REL-005",
        "event_time": "2026-01-15T10:24:00Z",
        "event_type": "vulnerability_observation",
        "description": "Synthetic server vulnerability association",
        "relationship_type": "HAS_VULNERABILITY",
        "source_id": "SRV-001",
        "source_type": "server",
        "source_name": "demo-server",
        "target_id": "VUL-001",
        "target_type": "vulnerability",
        "target_name": "CVE-DEMO-0001",
        "evidence_status": "derived",
        "is_synthetic": True,
    },
    {
        "RecordID": "demo-incident-006",
        "event_id": "EVT-006",
        "evidence_id": "EVD-006",
        "relationship_id": "REL-006",
        "event_time": "2026-01-15T10:25:00Z",
        "event_type": "incident_association",
        "description": "Synthetic incident-to-host association",
        "relationship_type": "INVOLVES",
        "source_id": "INC-001",
        "source_type": "incident",
        "source_name": "demo-incident",
        "target_id": "HOST-001",
        "target_type": "host",
        "target_name": "demo-host",
        "evidence_status": "unconfirmed",
        "is_synthetic": True,
    },
)


def write_demo_input(path: str | Path) -> Path:
    """Write deterministic JSONL fixtures marked synthetic by the caller."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        for record in DEMO_RECORDS:
            stream.write(json.dumps(record, sort_keys=True, allow_nan=False))
            stream.write("\n")
    return output
