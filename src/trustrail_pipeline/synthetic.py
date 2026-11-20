"""Deterministic, explicitly synthetic input for safe local demonstrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEMO_RECORDS: tuple[dict[str, Any], ...] = (
    {
        "RecordID": "demo-auth-001",
        "EventID": 4624,
        "Time": "2026-01-15T10:20:30Z",
        "UserName": "demo-user-01",
        "Computer": "demo-endpoint-01",
        "Status": "0x0",
        "LogonType": 3,
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
        "Protocol": 6,
        "SrcPort": 53000,
        "DstPort": 443,
        "Duration": 12,
        "SrcPackets": 14,
        "DstPackets": 11,
        "SrcBytes": 2048,
        "DstBytes": 8192,
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
