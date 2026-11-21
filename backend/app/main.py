from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "data" / "graph_fixture"


def read_jsonl(name: str) -> list[dict[str, Any]]:
    path = FIXTURE / name
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


ENTITIES = read_jsonl("entities.jsonl")
EVENTS = read_jsonl("events.jsonl")
RELATIONSHIPS = read_jsonl("relationships.jsonl")
EVIDENCE = read_jsonl("evidence.jsonl")

INCIDENTS: dict[str, dict[str, Any]] = {
    "INC-001": {
        "id": "INC-001",
        "title": "Synthetic workstation compromise",
        "severity": "high",
        "status": "INVESTIGATING",
        "source_entity_id": "HOST-001",
        "detection_time": "2026-11-14T08:40:00Z",
        "updated_at": "2026-11-14T08:41:00Z",
        "assigned_analyst": "Alex Rivera",
        "associated_alerts": ["EVT-016"],
    }
}
INVESTIGATIONS: dict[str, dict[str, Any]] = {
    "INV-001": {
        "id": "INV-001",
        "title": "HOST-001 suspicious activity",
        "status": "OPEN",
        "findings": "Unusual PowerShell execution is linked to HOST-001 and potentially reachable application infrastructure.",
        "notes": [],
        "entity_ids": ["HOST-001", "USR-001", "SRV-001", "APP-001"],
        "updated_at": "2026-11-14T08:41:00Z",
    }
}

app = FastAPI(title="TRUSTRAIL AI API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)


def entity_by_id(entity_id: str) -> dict[str, Any] | None:
    return next((entity for entity in ENTITIES if entity["id"] == entity_id), None)


def neighbors(entity_id: str, depth: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    depth = max(1, min(depth, 3))
    reached = {entity_id}
    frontier = {entity_id}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    original = [rel for rel in RELATIONSHIPS if rel["relationship_category"] == "original_entity"]

    for _ in range(depth):
        next_frontier: set[str] = set()
        for rel in original:
            source, target = rel["source_id"], rel["target_id"]
            if source in frontier:
                next_frontier.add(target)
            if target in frontier:
                next_frontier.add(source)
            if source in frontier or target in frontier:
                edge = {"id": rel["relationship_id"], "source": source, "target": target, "type": rel["relationship_type"]}
                if not any(existing["id"] == edge["id"] for existing in edges):
                    edges.append(edge)
        frontier = next_frontier - reached
        reached.update(frontier)
        if not frontier:
            break

    for entity_id_in_graph in reached:
        entity = entity_by_id(entity_id_in_graph)
        if entity:
            nodes.append({"id": entity["id"], "name": entity.get("name"), "type": entity["type"], "labels": [entity["type"]], "properties": entity})
    return nodes, edges


@app.get("/api/dashboard/overview")
def dashboard_overview() -> dict[str, Any]:
    high_risk = sum(entity.get("criticality") in {"high", "critical"} for entity in ENTITIES)
    high_severity_events = sum(str(event.get("severity", "")).lower() in {"high", "critical"} for event in EVENTS)
    return {
        "total_monitored_entities": len(ENTITIES),
        "total_devices": sum(entity["type"] == "Host" for entity in ENTITIES),
        "total_users": sum(entity["type"] == "User" for entity in ENTITIES),
        "total_servers": sum(entity["type"] == "Server" for entity in ENTITIES),
        "total_suspicious_ip_addresses": sum(entity["type"] == "IPAddress" for entity in ENTITIES),
        "detected_threats": high_severity_events,
        "active_incidents": sum(i["status"] not in {"RESOLVED", "CLOSED"} for i in INCIDENTS.values()),
        "critical_alerts": sum(str(event.get("severity", "")).lower() == "critical" for event in EVENTS),
        "high_risk_entities": high_risk,
        "current_investigation_count": len(INVESTIGATIONS),
    }


@app.get("/api/dashboard/threat-distribution")
def threat_distribution() -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for event in EVENTS:
        severity = str(event.get("severity") or "info").lower()
        category = str(event.get("event_type") or "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
    return {"by_severity": by_severity, "by_category": by_category}


@app.get("/api/dashboard/recent-activity")
def recent_activity() -> dict[str, Any]:
    items = sorted(EVENTS, key=lambda event: event.get("event_time") or "", reverse=True)[:10]
    return {"items": items}


@app.get("/api/graph/entities")
def graph_entities(entity_type: str | None = Query(default=None), risk_level: str | None = Query(default=None)) -> dict[str, Any]:
    items = ENTITIES
    if entity_type:
        items = [item for item in items if item["type"].lower() == entity_type.lower()]
    if risk_level:
        items = [item for item in items if str(item.get("criticality", "")).lower() == risk_level.lower()]
    return {"items": items}


@app.get("/api/graph/entity/{entity_id}")
def graph_entity(entity_id: str) -> dict[str, Any]:
    entity = entity_by_id(entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' was not found")
    return entity


@app.get("/api/graph/subgraph/{entity_id}")
def graph_subgraph(entity_id: str, depth: int = Query(default=2, ge=1, le=3)) -> dict[str, Any]:
    if not entity_by_id(entity_id):
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' was not found")
    nodes, edges = neighbors(entity_id, depth)
    return {"source_entity_id": entity_id, "depth": depth, "nodes": nodes, "edges": edges}


@app.get("/api/threats")
def threats(severity: str | None = None) -> dict[str, Any]:
    items = [
        {
            "id": event["event_id"],
            "threat_id": event["event_id"],
            "category": event["event_type"],
            "severity": event.get("severity") or "unknown",
            "risk_score": {"high": 85, "critical": 95, "medium": 55, "low": 25}.get(str(event.get("severity") or "").lower()),
            "entity_id": event.get("source_entity_id"),
            "associated_entities": [event.get("source_entity_id"), event.get("target_entity_id")],
            "detection_timestamp": event.get("event_time"),
            "description": event.get("description"),
        }
        for event in EVENTS
        if not severity or str(event.get("severity", "")).lower() == severity.lower()
    ]
    return {"items": items}


@app.get("/api/threats/{threat_id}")
def threat_detail(threat_id: str) -> dict[str, Any]:
    event = next((item for item in EVENTS if item["event_id"] == threat_id), None)
    if not event:
        raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' was not found")
    evidence = next((item for item in EVIDENCE if item["event_id"] == threat_id), None)
    return {"id": threat_id, "category": event["event_type"], "severity": event.get("severity"), "risk_score": 85, "explanation": event.get("description"), "evidence": evidence, "detection_timestamp": event.get("event_time")}


@app.get("/api/threats/evidence/{threat_id}")
def threat_evidence(threat_id: str) -> dict[str, Any]:
    evidence = [item for item in EVIDENCE if item["event_id"] == threat_id]
    return {"items": evidence}


@app.get("/api/blast-radius/{entity_id}")
def blast_radius(entity_id: str, depth: int = Query(default=3, ge=1, le=3)) -> dict[str, Any]:
    if not entity_by_id(entity_id):
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' was not found")
    nodes, edges = neighbors(entity_id, depth)
    affected = [node for node in nodes if node["id"] != entity_id]
    critical = [node for node in affected if str(node["properties"].get("criticality", "")).lower() in {"high", "critical"}]
    users = [node for node in affected if node["type"] == "User"]
    return {
        "source_entity_id": entity_id,
        "depth": depth,
        "nodes": nodes,
        "edges": edges,
        "affected_entities": affected,
        "reachable_entities_count": len(affected),
        "directly_connected_count": sum(edge["source"] == entity_id or edge["target"] == entity_id for edge in edges),
        "critical_assets_count": len(critical),
        "potentially_affected_users": users,
        "paths": [],
    }


class ContainmentIn(BaseModel):
    entity_id: str
    actions: list[str] = Field(default_factory=list)
    depth: int = Field(default=3, ge=1, le=3)


@app.post("/api/containment/simulate")
def containment_simulate(payload: ContainmentIn) -> dict[str, Any]:
    if not entity_by_id(payload.entity_id):
        raise HTTPException(status_code=404, detail=f"Entity '{payload.entity_id}' was not found")
    nodes, edges = neighbors(payload.entity_id, payload.depth)
    reachable = len(nodes)
    removed = len(edges) if payload.actions else 0
    remaining_edges = max(0, len(edges) - removed)
    remaining_nodes = max(1, reachable - min(len(payload.actions), max(0, reachable - 1)))
    critical = sum(str(node["properties"].get("criticality", "")).lower() in {"high", "critical"} for node in nodes)
    return {
        "before": {"reachable_entities_count": reachable, "critical_assets_remaining": critical, "potentially_affected_users": sum(n["type"] == "User" for n in nodes), "residual_risk": "reported by graph"},
        "after": {"reachable_entities_count": remaining_nodes, "critical_assets_remaining": max(0, critical - len(payload.actions)), "potentially_affected_users": 1 if remaining_nodes else 0, "residual_risk": "potential exposure remains"},
        "removed_relationships": edges[:removed],
        "removed_relationship_count": removed,
        "connectivity_removed": removed,
        "recommendation": "Simulation only: prioritize isolating the source host and blocking any confirmed suspicious address before restricting adjacent server access.",
    }


@app.get("/api/incidents")
def incidents() -> dict[str, Any]:
    return {"items": list(INCIDENTS.values())}


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str) -> dict[str, Any]:
    incident = INCIDENTS.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' was not found")
    return incident


@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(incident_id: str) -> None:
    if incident_id not in INCIDENTS:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' was not found")
    raise HTTPException(
        status_code=503,
        detail="Incident status updates are disabled until authentication and authorization are configured.",
    )


@app.get("/api/investigations")
def investigations() -> dict[str, Any]:
    return {"items": list(INVESTIGATIONS.values())}


@app.get("/api/investigations/{investigation_id}")
def investigation_detail(investigation_id: str) -> dict[str, Any]:
    investigation = INVESTIGATIONS.get(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' was not found")
    return investigation


class NoteIn(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)


@app.post("/api/investigations/{investigation_id}/notes")
def add_investigation_note(investigation_id: str, payload: NoteIn) -> dict[str, Any]:
    investigation = INVESTIGATIONS.get(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' was not found")
    investigation["notes"].append({"note": payload.note, "created_at": "2026-11-21T15:25:47Z"})
    return investigation
