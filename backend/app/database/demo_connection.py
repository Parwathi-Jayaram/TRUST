from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import Settings


class SyntheticFixtureConnection:
    """Read-only development connection backed by TRUSTRAIL's authorized JSONL fixture."""

    def __init__(self, settings: Settings):
        self.settings = settings
        root = Path(__file__).resolve().parents[3]
        fixture_dir = root / "data" / "graph_fixture"
        self.entities = self._load_jsonl(fixture_dir / "entities.jsonl")
        self.relationships = self._load_jsonl(fixture_dir / "relationships.jsonl")
        self.events = self._load_jsonl(fixture_dir / "events.jsonl")
        self.evidence = self._load_jsonl(fixture_dir / "evidence.jsonl")
        self.investigations: dict[str, dict[str, Any]] = {}
        self.incidents: dict[str, dict[str, Any]] = {}

        for entity in self.entities:
            if str(entity.get("type", "")).lower() == "incident":
                incident_id = entity["id"]
                self.incidents[incident_id] = {
                    **entity,
                    "title": entity.get("name") or incident_id,
                    "description": "Synthetic fixture incident record.",
                    "status": "NEW",
                    "priority": "medium",
                    "updated_at": "2026-11-20T19:16:39Z",
                    "created_at": "2026-11-20T19:16:39Z",
                    "status_history": [],
                    "is_synthetic": True,
                }

    @staticmethod
    def _load_jsonl(path: Path) -> list[dict[str, Any]]:
        with path.open("r", encoding="utf-8") as handle:
            return [
                json.loads(line)
                for line in handle
                if line.strip()
            ]

    async def health(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "configured": True,
            "database": "synthetic_fixture",
            "mode": "synthetic_demo",
            "synthetic": True,
        }

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    def _entity_props(self, entity: dict[str, Any]) -> dict[str, Any]:
        props = dict(entity)
        props["is_synthetic"] = True
        return props

    def _original_relationships(self) -> list[dict[str, Any]]:
        return [
            relationship
            for relationship in self.relationships
            if relationship.get("relationship_category") == "original_entity"
        ]

    async def execute_read(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        parameters = parameters or {}

        if "active_incident_statuses" in query:
            entities = self.entities
            device_types = {str(value).lower() for value in parameters["device_types"]}
            active_statuses = {str(value).upper() for value in parameters["active_incident_statuses"]}
            incident_count = sum(
                1
                for incident in self.incidents.values()
                if str(incident.get("status", "")).upper() in active_statuses
            )
            return [{
                "total_monitored_entities": len(entities),
                "devices": sum(
                    1 for entity in entities
                    if str(entity.get("type", "")).lower() in device_types
                ),
                "users": sum(
                    1 for entity in entities
                    if str(entity.get("type", "")).lower() == "user"
                ),
                "servers": sum(
                    1 for entity in entities
                    if str(entity.get("type", "")).lower() == "server"
                ),
                "active_incidents": incident_count,
                "current_investigation_count": len(self.investigations),
            }]

        if "DASHBOARD_RECENT_EVENTS" in query or (
            "event.event_id AS event_id" in query
            and "LIMIT $limit" in query
        ):
            limit = int(parameters.get("limit", 20))
            events = sorted(
                self.events,
                key=lambda event: str(event.get("event_time") or ""),
                reverse=True,
            )[:limit]
            return [{
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "event_time": event["event_time"],
                "severity": event["severity"],
                "description": event["description"],
                "is_synthetic": True,
            } for event in events]

        if "investigation.id AS investigation_id" in query:
            limit = int(parameters.get("limit", 20))
            investigations = sorted(
                self.investigations.values(),
                key=lambda item: str(item.get("updated_at") or ""),
                reverse=True,
            )[:limit]
            return [{
                "investigation_id": item["id"],
                "title": item["title"],
                "status": item["status"],
                "updated_at": item["updated_at"],
                "is_synthetic": True,
            } for item in investigations]

        if "total_nodes" in query:
            return [{
                "total_nodes": len(self.entities) + len(self.events) + len(self.evidence),
                "total_entities": len(self.entities),
                "total_events": len(self.events),
                "total_evidence": len(self.evidence),
                "total_relationships": len(self.relationships),
            }]

        if "SKIP $skip" in query and "MATCH (entity:GraphNode:Entity)" in query:
            entity_type = parameters.get("entity_type")
            risk_level = parameters.get("risk_level")
            entities = list(self.entities)
            if entity_type:
                entities = [
                    entity for entity in entities
                    if str(entity.get("type", "")).lower() == str(entity_type).lower()
                ]
            if risk_level:
                entities = [
                    entity for entity in entities
                    if str(entity.get("risk_level", "")).lower() == str(risk_level).lower()
                ]
            start = int(parameters.get("skip", 0))
            limit = int(parameters.get("limit", 50))
            return [
                {"labels": ["GraphNode", "Entity"], "properties": self._entity_props(entity)}
                for entity in sorted(entities, key=lambda item: str(item["id"]))[start:start + limit]
            ]

        if "labeled_entities" in query:
            return [{
                "labeled_entities": sum(
                    1 for entity in self.entities
                    if entity.get("risk_level") is not None
                )
            }]

        if "source_labels" in query and "OPTIONAL MATCH path" in query:
            source_id = parameters.get("entity_id")
            source = next(
                (item for item in self.entities if item["id"] == source_id),
                None,
            )
            if source is None:
                return []
            depth = 6
            for value in range(1, 7):
                if f"[*1..{value}]" in query:
                    depth = value
                    break
            excluded = set(parameters.get("excluded_entity_ids", []))
            paths = self._undirected_paths(source_id, depth, excluded)
            limit = int(parameters.get("limit", 300))
            rows = []
            for path in paths[:limit]:
                rows.append({
                    "source_labels": ["GraphNode", "Entity"],
                    "source_properties": self._entity_props(source),
                    "nodes": [self._path_node(node_id) for node_id in path],
                    "relationships": [
                        self._path_relationship(path[index], path[index + 1], index)
                        for index in range(len(path) - 1)
                    ],
                })
            return rows

        if "GRAPH_ENTITY" in query or (
            "RETURN labels(entity)" in query
            and "properties(entity)" in query
        ):
            entity_id = parameters.get("entity_id")
            entity = next((item for item in self.entities if item["id"] == entity_id), None)
            if entity is None:
                return []
            return [{
                "labels": ["GraphNode", "Entity"],
                "properties": self._entity_props(entity),
            }]

        if "OPTIONAL MATCH (entity)-[relationship]-(neighbor:GraphNode)" in query:
            entity_id = parameters.get("entity_id")
            entity = next(
                (item for item in self.entities if item["id"] == entity_id),
                None,
            )
            if entity is None:
                return []
            is_neighbor_query = "entity_labels" in query
            rows = []
            for relationship in self._original_relationships():
                if relationship["source_id"] == entity_id or relationship["target_id"] == entity_id:
                    neighbor_id = (
                        relationship["target_id"]
                        if relationship["source_id"] == entity_id
                        else relationship["source_id"]
                    )
                    neighbor = next(
                        (item for item in self.entities if item["id"] == neighbor_id),
                        None,
                    )
                    if neighbor is None:
                        continue
                    neighbor_data = {
                        "neighbor_labels": ["GraphNode", "Entity"],
                        "neighbor_properties": self._entity_props(neighbor),
                        "source_id": relationship["source_id"],
                        "target_id": relationship["target_id"],
                    }
                    if is_neighbor_query:
                        rows.append({
                            **neighbor_data,
                            "entity_labels": ["GraphNode", "Entity"],
                            "entity_properties": self._entity_props(entity),
                            "relationship_type": relationship["relationship_type"],
                            "relationship_properties": relationship,
                        })
                    else:
                        rows.append({
                            **neighbor_data,
                            "type": relationship["relationship_type"],
                            "properties": relationship,
                        })
            if rows:
                return rows
            if is_neighbor_query:
                return [{
                    "entity_labels": ["GraphNode", "Entity"],
                    "entity_properties": self._entity_props(entity),
                    "neighbor_labels": None,
                    "neighbor_properties": None,
                    "relationship_type": None,
                    "relationship_properties": None,
                    "source_id": None,
                    "target_id": None,
                }]
            return [{
                "type": None,
                "properties": None,
                "neighbor_labels": None,
                "neighbor_properties": None,
                "source_id": None,
                "target_id": None,
            }]

        if "properties(event) AS event" in query:
            skip = int(parameters.get("skip", 0))
            limit = int(parameters.get("limit", 20))
            events = sorted(
                self.events,
                key=lambda event: str(event.get("event_time") or ""),
                reverse=True,
            )[skip:skip + limit]
            return [{"event": event} for event in events]

        if "event_id: $threat_id" in query:
            threat_id = parameters.get("threat_id")
            if "SUPPORTED_BY" in query:
                evidence_ids = [
                    event["evidence_id"]
                    for event in self.events
                    if event["event_id"] == threat_id
                ]
                evidence = [
                    item for item in self.evidence
                    if item["evidence_id"] in evidence_ids
                ]
                return [{"evidence_id": item["evidence_id"], "evidence": item} for item in evidence]
            if "OBSERVED_ON" in query:
                event = next((item for item in self.events if item["event_id"] == threat_id), None)
                if event is None:
                    return []
                ids = {
                    event.get("source_entity_id"),
                    event.get("target_entity_id"),
                }
                entities = [item for item in self.entities if item["id"] in ids]
                return [
                    {"entity_id": item["id"], "labels": ["GraphNode", "Entity"], "properties": self._entity_props(item)}
                    for item in entities
                ]
            event = next((item for item in self.events if item["event_id"] == threat_id), None)
            return [{"event": event}] if event else []

        if "INCIDENT_LIST" in query or (
            "incident:GraphNode:Entity" in query
            and "properties(incident) AS incident" in query
            and "active_incident_statuses" not in query
        ):
            status = parameters.get("status")
            priority = parameters.get("priority")
            incidents = list(self.incidents.values())
            if status:
                incidents = [item for item in incidents if str(item.get("status", "")).upper() == str(status).upper()]
            if priority:
                incidents = [item for item in incidents if str(item.get("priority", "")).lower() == str(priority).lower()]
            incidents.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
            start = int(parameters.get("skip", 0))
            limit = int(parameters.get("limit", 50))
            return [{"incident": dict(item)} for item in incidents[start:start + limit]]

        if "incident_id" in parameters:
            incident_id = parameters["incident_id"]
            incident = self.incidents.get(incident_id)
            if "RETURN incident.status AS status" in query:
                return [{"status": incident["status"]}] if incident else []
            if "OPTIONAL MATCH (event:GraphNode:SecurityEvent {event_id: incident.related_event_id})" in query:
                if incident is None:
                    return []
                event_id = incident.get("related_event_id")
                event = next((item for item in self.events if item["event_id"] == event_id), None)
                return [{"incident": incident, "event": event}]
            if incident is None:
                return []
            return [{"incident": dict(incident)}]

        if "ENTITY_TYPES_BY_IDS" in query or "entity.id IN $entity_ids" in query:
            ids = set(parameters.get("entity_ids", []))
            return [
                {"id": entity["id"], "type": entity["type"]}
                for entity in self.entities
                if entity["id"] in ids
            ]

        if "ENTITY_TYPE_BY_ID" in query:
            entity_id = parameters.get("entity_id")
            entity = next((item for item in self.entities if item["id"] == entity_id), None)
            return [{"id": entity["id"], "type": entity["type"], "properties": entity}] if entity else []

        if "INVESTIGATION_LIST" in query or (
            "investigation:GraphNode:Entity" in query
            and "properties(investigation) AS investigation" in query
        ):
            status = parameters.get("status")
            alert_id = parameters.get("alert_id")
            investigations = list(self.investigations.values())
            if status:
                investigations = [item for item in investigations if str(item.get("status", "")).upper() == str(status).upper()]
            if alert_id:
                investigations = [item for item in investigations if item.get("related_event_id") == alert_id]
            investigations.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
            start = int(parameters.get("skip", 0))
            limit = int(parameters.get("limit", 50))
            return [{"investigation": dict(item)} for item in investigations[start:start + limit]]

        if "investigation_id" in parameters:
            investigation_id = parameters["investigation_id"]
            investigation = self.investigations.get(investigation_id)
            if "RETURN investigation.status AS status" in query:
                return [{"status": investigation["status"]}] if investigation else []
            if "UNWIND coalesce(investigation.evidence_ids" in query:
                if investigation is None:
                    return []
                evidence_ids = investigation.get("evidence_ids", [])
                evidence = [item for item in self.evidence if item["evidence_id"] in evidence_ids]
                return [{"evidence": item} for item in evidence]
            if investigation is None:
                return []
            return [{"investigation": dict(investigation)}]

        if "MATCH path =" in query:
            source_id = parameters.get("source_id")
            target_id = parameters.get("target_id")
            depth = 6
            for value in range(1, 7):
                if f"[*1..{value}]" in query:
                    depth = value
                    break
            limit = int(parameters.get("limit", 20))
            paths = self._directed_paths(source_id, target_id, depth)
            return [
                {
                    "nodes": [self._path_node(node_id) for node_id in path],
                    "relationships": [
                        self._path_relationship(path[index], path[index + 1], index)
                        for index in range(len(path) - 1)
                    ],
                    "depth": len(path) - 1,
                }
                for path in paths[:limit]
            ]

        if "MATCH (source:GraphNode:Entity" in query or "MATCH (source:GraphNode" in query:
            source_id = parameters.get("entity_id") or parameters.get("source_id")
            target_id = parameters.get("target_id")
            depth = 6
            for value in range(1, 7):
                if f"[*1..{value}]" in query:
                    depth = value
                    break
            excluded = set(parameters.get("excluded_entity_ids", []))
            if "MATCH path =" in query or "-[*1.." in query:
                if target_id:
                    paths = self._directed_paths(source_id, target_id, depth)
                    limit = int(parameters.get("limit", 20))
                    return [
                        {
                            "nodes": [self._path_node(node_id) for node_id in path],
                            "relationships": [
                                self._path_relationship(path[index], path[index + 1], index)
                                for index in range(len(path) - 1)
                            ],
                            "depth": len(path) - 1,
                        }
                        for path in paths[:limit]
                    ]
            source = next((item for item in self.entities if item["id"] == source_id), None)
            if source is None:
                return []
            paths = self._undirected_paths(source_id, depth, excluded)
            limit = int(parameters.get("limit", 300))
            rows = []
            for path in paths[:limit]:
                relationships = [
                    self._path_relationship(path[index], path[index + 1], index)
                    for index in range(len(path) - 1)
                ]
                rows.append({
                    "source_labels": ["GraphNode", "Entity"],
                    "source_properties": self._entity_props(source),
                    "nodes": [self._path_node(node_id) for node_id in path],
                    "relationships": relationships,
                })
            return rows

        return []

    def _adjacent(self, entity_id: str, directed: bool = False) -> list[tuple[str, dict[str, Any]]]:
        neighbors = []
        for relationship in self._original_relationships():
            if relationship["source_id"] == entity_id:
                neighbors.append((relationship["target_id"], relationship))
            elif not directed and relationship["target_id"] == entity_id:
                neighbors.append((relationship["source_id"], relationship))
        return neighbors

    def _undirected_paths(
        self,
        source_id: str,
        depth: int,
        excluded: set[str],
    ) -> list[list[str]]:
        if source_id in excluded:
            return []
        paths: list[list[str]] = []
        queue = [(source_id, [source_id])]
        while queue:
            current, path = queue.pop(0)
            if len(path) - 1 >= depth:
                continue
            for neighbor, _ in self._adjacent(current, directed=False):
                if neighbor in excluded or neighbor in path:
                    continue
                next_path = path + [neighbor]
                paths.append(next_path)
                queue.append((next_path[-1], next_path))
        return paths

    def _directed_paths(
        self,
        source_id: str,
        target_id: str,
        depth: int,
    ) -> list[list[str]]:
        paths: list[list[str]] = []
        queue = [(source_id, [source_id])]
        while queue:
            current, path = queue.pop(0)
            if len(path) - 1 >= depth:
                continue
            for neighbor, _ in self._adjacent(current, directed=True):
                if neighbor in path:
                    continue
                next_path = path + [neighbor]
                if neighbor == target_id:
                    paths.append(next_path)
                else:
                    queue.append((neighbor, next_path))
        return sorted(paths, key=len)

    def _path_node(self, entity_id: str) -> dict[str, Any]:
        entity = next(item for item in self.entities if item["id"] == entity_id)
        return {
            "id": entity_id,
            "labels": ["GraphNode", "Entity"],
            "properties": self._entity_props(entity),
        }

    def _path_relationship(
        self,
        source_id: str,
        target_id: str,
        index: int,
    ) -> dict[str, Any]:
        relationship = next(
            (
                item for item in self._original_relationships()
                if (
                    item["source_id"] == source_id
                    and item["target_id"] == target_id
                )
                or (
                    item["target_id"] == source_id
                    and item["source_id"] == target_id
                )
            ),
            None,
        )
        if relationship is None:
            return {
                "id": f"demo-relation-{index}",
                "type": "RELATED_TO",
                "source_id": source_id,
                "target_id": target_id,
                "properties": {"relationship_category": "original_entity", "is_synthetic": True},
            }
        return {
            "id": relationship["relationship_id"],
            "type": relationship["relationship_type"],
            "source_id": relationship["source_id"],
            "target_id": relationship["target_id"],
            "properties": relationship,
        }

    async def execute_write(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        parameters = parameters or {}

        if "CREATE (incident:GraphNode:Entity)" in query:
            properties = dict(parameters["properties"])
            properties["is_synthetic"] = True
            event_id = parameters.get("event_id")
            if event_id is not None and not any(
                event["event_id"] == event_id for event in self.events
            ):
                return []
            incident_id = properties["id"]
            self.incidents[incident_id] = properties
            self.entities.append({
                "id": incident_id,
                "name": properties["title"],
                "type": "Incident",
                "synthetic": True,
            })
            return [{"incident": dict(properties)}]

        if "SET incident.status = $new_status" in query:
            incident = self.incidents.get(parameters["incident_id"])
            if incident is None or str(incident.get("status", "UNSET")) != str(parameters["expected_status"]):
                return []
            incident["status"] = parameters["new_status"]
            incident["updated_at"] = parameters["updated_at"]
            incident.setdefault("status_history", []).append(parameters["audit_entry"])
            return [{"incident": dict(incident)}]

        if "SET incident.priority = $priority" in query:
            incident = self.incidents.get(parameters["incident_id"])
            if incident is None:
                return []
            incident["priority"] = parameters["priority"]
            incident["updated_at"] = parameters["updated_at"]
            incident.setdefault("status_history", []).append(parameters["audit_entry"])
            return [{"incident": dict(incident)}]

        if "CREATE (investigation:GraphNode:Entity)" in query:
            properties = dict(parameters["properties"])
            properties["is_synthetic"] = True
            alert_id = parameters.get("alert_id")
            if alert_id is not None and not any(
                event["event_id"] == alert_id for event in self.events
            ):
                return []
            entity_ids = set(parameters["entity_ids"])
            if not entity_ids.issubset({entity["id"] for entity in self.entities}):
                return []
            investigation_id = properties["id"]
            self.investigations[investigation_id] = properties
            return [{"investigation": dict(properties)}]

        if "SET investigation.notes = coalesce(investigation.notes, []) + [$note_entry]" in query:
            investigation = self.investigations.get(parameters["investigation_id"])
            if investigation is None:
                return []
            investigation.setdefault("notes", []).append(parameters["note_entry"])
            investigation.setdefault("audit_history", []).append(parameters["audit_entry"])
            investigation["updated_at"] = parameters["updated_at"]
            return [{"investigation": dict(investigation)}]

        if "SET investigation.evidence_ids =" in query:
            investigation = self.investigations.get(parameters["investigation_id"])
            if investigation is None:
                return []
            if not any(
                evidence["evidence_id"] == parameters["evidence_id"]
                for evidence in self.evidence
            ):
                return []
            evidence_ids = investigation.setdefault("evidence_ids", [])
            if parameters["evidence_id"] not in evidence_ids:
                evidence_ids.append(parameters["evidence_id"])
                investigation.setdefault("audit_history", []).append(parameters["audit_entry"])
                investigation["updated_at"] = parameters["updated_at"]
            return [{"investigation": dict(investigation), "already_attached": False}]

        if "SET investigation.status = $new_status" in query:
            investigation = self.investigations.get(parameters["investigation_id"])
            if investigation is None or investigation["status"] != parameters["expected_status"]:
                return []
            investigation["status"] = parameters["new_status"]
            investigation.setdefault("audit_history", []).append(parameters["audit_entry"])
            investigation["updated_at"] = parameters["updated_at"]
            return [{"investigation": dict(investigation)}]

        return []
