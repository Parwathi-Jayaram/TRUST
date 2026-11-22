from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import ValidationError

from ..database import queries
from ..database.neo4j_connection import Neo4jConnection
from ..schemas.report_schema import (
    InvestigationReportSnapshot,
    ReportAIExplanation,
    ReportEntity,
    ReportEvidence,
    ReportFinding,
    ReportGraph,
    ReportInvestigation,
    ReportPath,
    ReportRelationship,
    ReportRiskAssessment,
    ReportThreatIntelligence,
)
from .graph_service import GraphService
from .investigation_service import InvestigationNotFound, InvestigationService
from .member4_detection import (
    DetectionEngineUnavailable,
    DetectionInferenceError,
    Member4DetectionEngine,
)
from .threat_service import ThreatService

logger = logging.getLogger(__name__)

MAX_REPORT_SNAPSHOT_BYTES = 1_000_000
MAX_REPORT_LINKED_ENTITIES = 10
MAX_REPORT_GRAPH_NODES = 50
MAX_REPORT_GRAPH_RELATIONSHIPS = 100
MAX_REPORT_PATHS = 20
MAX_REPORT_EVIDENCE = 100
MAX_REPORT_TEXT = 4_000
MAX_REPORT_TEXT_LIST = 20

_BEARER_SECRET = re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+\S+")
_ASSIGNED_SECRET = re.compile(
    r"""(?i)\b(password|passphrase|api[_-]?key|client[_-]?secret|secret|token)\b"""
    r"""["']?\s*[:=]\s*["']?([^\s"',;}]+)"""
)
_KNOWN_TOKEN = re.compile(
    r"(?i)\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9_-]{20,})\b"
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ReportSnapshotError(RuntimeError):
    pass


def safe_report_text(value: Any, limit: int = MAX_REPORT_TEXT) -> str | None:
    if value is None:
        return None
    text = _CONTROL_CHARS.sub("", str(value)).strip()
    text = _BEARER_SECRET.sub("Authorization: Bearer [REDACTED]", text)
    text = _ASSIGNED_SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _KNOWN_TOKEN.sub("[REDACTED]", text)
    if not text:
        return None
    if len(text) > limit:
        text = f"{text[:limit - 3]}..."
    return text


def _safe_text_list(values: Any, limit: int = MAX_REPORT_TEXT_LIST) -> list[str]:
    if not isinstance(values, (list, tuple)):
        values = [values] if values is not None else []
    return [
        text
        for value in values[:limit]
        if (text := safe_report_text(value)) is not None
    ]


def _safe_number(value: Any, minimum: float, maximum: float) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if minimum <= number <= maximum else None


def _report_entity(value: Any) -> ReportEntity | None:
    if not isinstance(value, dict):
        return None
    raw_properties = value.get("properties")
    properties: dict[str, Any] = raw_properties if isinstance(raw_properties, dict) else value
    entity_id = safe_report_text(value.get("id") or properties.get("id"), 200)
    if not entity_id:
        return None
    labels = value.get("labels") or []
    if not isinstance(labels, list):
        labels = []
    entity_type = safe_report_text(properties.get("type"), 100)
    if not entity_type:
        entity_type = next(
            (
                safe_report_text(label, 100)
                for label in labels
                if label not in {"GraphNode", "Entity", "SecurityEvent", "Evidence"}
            ),
            None,
        )
    return ReportEntity(
        id=entity_id,
        name=safe_report_text(properties.get("name"), 500),
        type=entity_type,
        labels=_safe_text_list(labels, 10),
        criticality=safe_report_text(properties.get("criticality"), 50),
        risk_level=safe_report_text(properties.get("risk_level"), 50),
        is_synthetic=properties.get("is_synthetic")
        if isinstance(properties.get("is_synthetic"), bool)
        else None,
    )


def _report_relationship(value: Any) -> ReportRelationship | None:
    if not isinstance(value, dict):
        return None
    raw_properties = value.get("properties")
    properties: dict[str, Any] = raw_properties if isinstance(raw_properties, dict) else {}
    source_id = safe_report_text(value.get("source_id"), 200)
    target_id = safe_report_text(value.get("target_id"), 200)
    relation_type = safe_report_text(value.get("type"), 200)
    if not source_id or not target_id or not relation_type:
        return None
    evidence_ids = properties.get("evidence_ids")
    if not isinstance(evidence_ids, list):
        evidence_id = properties.get("evidence_id")
        evidence_ids = [evidence_id] if evidence_id else []
    return ReportRelationship(
        id=safe_report_text(value.get("id") or properties.get("relationship_id"), 200),
        type=relation_type,
        source_id=source_id,
        target_id=target_id,
        evidence_ids=_safe_text_list(evidence_ids, 20),
    )


def _report_finding(threat: dict[str, Any]) -> ReportFinding:
    event_id = safe_report_text(threat.get("event_id") or threat.get("threat_id"), 200)
    if not event_id:
        raise ReportSnapshotError("Member 4 returned a finding without an event ID.")
    return ReportFinding(
        event_id=event_id,
        event_type=safe_report_text(threat.get("event_type"), 200),
        event_time=safe_report_text(threat.get("event_time"), 100),
        severity=safe_report_text(threat.get("severity"), 50),
        summary=safe_report_text(threat.get("description")),
        evidence_id=safe_report_text(threat.get("evidence_id"), 200),
        risk_score=_safe_number(threat.get("risk_score"), 0, 100),
        risk_level=safe_report_text(threat.get("risk_level"), 50),
        confidence=_safe_number(threat.get("confidence"), 0, 1),
        model_name=safe_report_text(threat.get("model_name"), 200),
        model_version=safe_report_text(threat.get("model_version"), 100),
        explanation=_safe_text_list(threat.get("explanation")),
        limitations=_safe_text_list(threat.get("limitations")),
        is_synthetic=threat.get("is_synthetic")
        if isinstance(threat.get("is_synthetic"), bool)
        else None,
    )


class InvestigationReportDataService:
    def __init__(
        self,
        database: Neo4jConnection,
        detection_engine: Member4DetectionEngine,
        max_graph_depth: int,
    ):
        self.database = database
        self.investigations = InvestigationService(database, max_graph_depth)
        self.graph = GraphService(database, max_graph_depth)
        self.threats = ThreatService(database, detection_engine)
        self.max_graph_depth = min(3, max_graph_depth)

    async def get_snapshot(
        self,
        investigation_id: str,
    ) -> tuple[InvestigationReportSnapshot, str, bool]:
        rows = await self.database.execute_read(
            queries.INVESTIGATION_REPORT_LATEST_SNAPSHOT,
            parameters={"investigation_id": investigation_id},
        )
        snapshot_json = rows[0].get("snapshot_json") if rows else None
        if snapshot_json:
            if len(snapshot_json.encode("utf-8")) > MAX_REPORT_SNAPSHOT_BYTES:
                raise ReportSnapshotError("Stored report snapshot exceeds the allowed size.")
            try:
                snapshot = InvestigationReportSnapshot.model_validate_json(snapshot_json)
            except ValidationError as exc:
                logger.error("Stored report snapshot failed validation.")
                raise ReportSnapshotError("Stored report snapshot is invalid.") from exc
            if snapshot.investigation.id != investigation_id:
                raise ReportSnapshotError("Stored report snapshot does not match the requested investigation.")
            return snapshot, self._snapshot_hash(snapshot), False

        snapshot = await self._build_snapshot(investigation_id)
        return snapshot, self._snapshot_hash(snapshot), True

    async def record_generated(
        self,
        snapshot: InvestigationReportSnapshot,
        snapshot_hash: str,
        persist_snapshot: bool,
    ) -> None:
        now = self._now()
        audit_entry = self._dump({
            "action": "report_generated",
            "previous_value": None,
            "new_value": snapshot.report_id,
            "note": f"snapshot_sha256={snapshot_hash}",
            "actor": "backend_api",
            "timestamp": now,
        })
        if persist_snapshot:
            snapshot_json = snapshot.model_dump_json()
            if len(snapshot_json.encode("utf-8")) > MAX_REPORT_SNAPSHOT_BYTES:
                raise ReportSnapshotError("Report snapshot exceeds the allowed size.")
            rows = await self.database.execute_write(
                queries.INVESTIGATION_REPORT_STORE_SNAPSHOT,
                parameters={
                    "investigation_id": snapshot.investigation.id,
                    "report_id": snapshot.report_id,
                    "generated_at": snapshot.snapshot_captured_at,
                    "snapshot_json": snapshot_json,
                    "snapshot_sha256": snapshot_hash,
                    "is_synthetic": (
                        True if snapshot.provenance == "synthetic"
                        else False if snapshot.provenance == "non_synthetic"
                        else None
                    ),
                    "audit_entry": audit_entry,
                },
            )
        else:
            rows = await self.database.execute_write(
                queries.INVESTIGATION_REPORT_AUDIT,
                parameters={
                    "investigation_id": snapshot.investigation.id,
                    "audit_entry": audit_entry,
                },
            )
        if not rows:
            raise InvestigationNotFound(snapshot.investigation.id)

    async def _build_snapshot(
        self,
        investigation_id: str,
    ) -> InvestigationReportSnapshot:
        investigation = await self.investigations.get_investigation(investigation_id)
        limitations: list[str] = []
        linked_ids = []
        for item in investigation.get("entity_ids", []):
            if isinstance(item, str) and item and len(item) <= 200:
                linked_ids.append(item)
            else:
                limitations.append("One or more linked entity IDs were invalid and were omitted.")
        if len(linked_ids) > MAX_REPORT_LINKED_ENTITIES:
            limitations.append(
                f"Graph collection was limited to {MAX_REPORT_LINKED_ENTITIES} linked entities."
            )
            linked_ids = linked_ids[:MAX_REPORT_LINKED_ENTITIES]

        evidence = await self.investigations.get_evidence(
            investigation_id,
            limit=MAX_REPORT_EVIDENCE + 1,
        )
        if len(evidence) > MAX_REPORT_EVIDENCE:
            limitations.append(
                f"Evidence was limited to the first {MAX_REPORT_EVIDENCE} records."
            )
            evidence = evidence[:MAX_REPORT_EVIDENCE]
        report_evidence = [self._report_evidence(item) for item in evidence]
        raw_attached_ids = investigation.get("evidence_ids", [])
        if not isinstance(raw_attached_ids, list):
            raw_attached_ids = []
        if len(raw_attached_ids) > MAX_REPORT_EVIDENCE:
            limitations.append(
                f"Attached evidence references were limited to {MAX_REPORT_EVIDENCE} records."
            )
        attached_ids = {
            item
            for item in raw_attached_ids[:MAX_REPORT_EVIDENCE]
            if isinstance(item, str) and item and len(item) <= 200
        }
        returned_ids = {item.evidence_id for item in report_evidence}
        missing_evidence = sorted(attached_ids - returned_ids)
        if missing_evidence:
            limitations.append(
                f"{len(missing_evidence)} attached evidence reference(s) were unavailable at capture time."
            )

        graph = await self._collect_graph(linked_ids)
        findings, risk = await self._collect_risk(investigation.get("related_event_id"))
        threat_intelligence = ReportThreatIntelligence(
            status="unavailable",
            provider=None,
            findings=[],
            message="No Member 3 threat-intelligence provider is configured in this backend.",
            limitations=["An unavailable provider is not evidence that no threat intelligence exists."],
        )
        ai = ReportAIExplanation(
            status="unavailable",
            provider=None,
            message="No investigation-level AI summary provider is configured in this backend.",
            limitations=["Member 4 model explanations are included only when returned for a linked event; no AI narrative was generated."],
        )
        if risk.status in {"unavailable", "empty"}:
            limitations.extend(risk.limitations)
        if graph.status in {"unavailable", "empty", "partial"}:
            limitations.extend(graph.limitations)
        if threat_intelligence.status == "unavailable":
            limitations.extend(threat_intelligence.limitations)
        if ai.status == "unavailable":
            limitations.extend(ai.limitations)

        report_investigation = ReportInvestigation(
            id=safe_report_text(investigation.get("id"), 200) or investigation_id,
            title=safe_report_text(investigation.get("title"), 500) or investigation_id,
            status=safe_report_text(investigation.get("status"), 50),
            created_at=safe_report_text(investigation.get("created_at"), 100),
            updated_at=safe_report_text(investigation.get("updated_at"), 100),
            related_event_id=safe_report_text(investigation.get("related_event_id"), 200),
            entity_ids=linked_ids,
            evidence_ids=sorted(attached_ids)[:MAX_REPORT_EVIDENCE],
            is_synthetic=investigation.get("is_synthetic")
            if isinstance(investigation.get("is_synthetic"), bool)
            else None,
        )
        provenance = self._provenance(
            [
                report_investigation.is_synthetic,
                *(item.is_synthetic for item in graph.nodes),
                *(item.is_synthetic for item in report_evidence),
                *(item.is_synthetic for item in findings),
            ]
        )
        summary = self._executive_summary(
            report_investigation,
            findings,
            risk,
            graph,
            report_evidence,
            provenance,
        )
        partial = any(
            status in {"unavailable", "partial"}
            for status in (
                risk.status,
                graph.status,
                threat_intelligence.status,
                ai.status,
            )
        )
        return InvestigationReportSnapshot(
            report_id=f"RPT-{uuid4().hex}",
            snapshot_captured_at=self._now(),
            investigation=report_investigation,
            executive_summary=summary,
            findings=findings,
            risk_assessment=risk,
            threat_intelligence=threat_intelligence,
            graph=graph,
            ai_explanation=ai,
            evidence=report_evidence,
            provenance=provenance,
            limitations=self._unique_texts(limitations, 50),
            partial=partial,
        )

    async def _collect_graph(self, linked_ids: list[str]) -> ReportGraph:
        if not linked_ids:
            return ReportGraph(
                status="empty",
                starting_entity=None,
                depth=0,
                limitations=["No graph entities are linked to this investigation."],
            )

        root_id = linked_ids[0]
        depth = max(1, self.max_graph_depth)
        subgraph = await self.graph.get_subgraph(
            entity_id=root_id,
            depth=depth,
            limit=100,
        )
        if subgraph is None:
            return ReportGraph(
                status="empty",
                starting_entity=None,
                depth=depth,
                limitations=["The linked starting entity was not present in the graph at capture time."],
            )

        starting_entity = _report_entity(subgraph.get("root"))
        node_map: dict[str, ReportEntity] = {}
        if starting_entity:
            node_map[starting_entity.id] = starting_entity
        for item in subgraph.get("nodes", [])[:MAX_REPORT_GRAPH_NODES]:
            entity = _report_entity(item)
            if entity:
                node_map.setdefault(entity.id, entity)
        relationships: dict[tuple[str, str, str, str], ReportRelationship] = {}
        for item in subgraph.get("relationships", [])[:MAX_REPORT_GRAPH_RELATIONSHIPS]:
            relationship = _report_relationship(item)
            if relationship:
                relationships.setdefault(
                    (
                        relationship.id or "",
                        relationship.source_id,
                        relationship.target_id,
                        relationship.type,
                    ),
                    relationship,
                )

        paths: list[ReportPath] = []
        path_targets = linked_ids[1:MAX_REPORT_LINKED_ENTITIES]
        for target_id in path_targets:
            result = await self.graph.find_attack_paths(
                source_id=root_id,
                target_id=target_id,
                depth=depth,
                limit=5,
            )
            for path_data in result.get("paths", []):
                if len(paths) >= MAX_REPORT_PATHS:
                    break
                path_nodes = [
                    entity
                    for item in path_data.get("nodes", [])
                    if (entity := _report_entity(item)) is not None
                ]
                path_relationships = [
                    relationship
                    for item in path_data.get("relationships", [])
                    if (relationship := _report_relationship(item)) is not None
                ]
                if (
                    len(path_nodes) >= 2
                    and len(path_relationships) == len(path_nodes) - 1
                    and 1 <= int(path_data.get("depth", 0)) <= depth
                ):
                    paths.append(ReportPath(
                        nodes=path_nodes[:4],
                        relationships=path_relationships[:3],
                        depth=int(path_data["depth"]),
                    ))
                    for entity in path_nodes:
                        node_map.setdefault(entity.id, entity)
                    for relationship in path_relationships:
                        relationships.setdefault(
                            (
                                relationship.id or "",
                                relationship.source_id,
                                relationship.target_id,
                                relationship.type,
                            ),
                            relationship,
                        )
            if len(paths) >= MAX_REPORT_PATHS:
                break

        limitations = []
        if len(subgraph.get("nodes", [])) > MAX_REPORT_GRAPH_NODES:
            limitations.append(
                f"Graph nodes were limited to {MAX_REPORT_GRAPH_NODES} records."
            )
        if len(subgraph.get("relationships", [])) > MAX_REPORT_GRAPH_RELATIONSHIPS:
            limitations.append(
                f"Graph relationships were limited to {MAX_REPORT_GRAPH_RELATIONSHIPS} records."
            )
        if len(node_map) > MAX_REPORT_GRAPH_NODES:
            limitations.append(
                f"Graph nodes were limited to {MAX_REPORT_GRAPH_NODES} records."
            )
        if len(relationships) > MAX_REPORT_GRAPH_RELATIONSHIPS:
            limitations.append(
                f"Graph relationships were limited to {MAX_REPORT_GRAPH_RELATIONSHIPS} records."
            )
        if len(linked_ids) > MAX_REPORT_LINKED_ENTITIES:
            limitations.append(
                f"Directed paths were checked for at most {MAX_REPORT_LINKED_ENTITIES - 1} linked targets."
            )
        if not relationships:
            limitations.append(
                f"No qualifying graph relationships were returned within {depth} hop(s)."
            )
        return ReportGraph(
            status="available" if relationships else "empty",
            starting_entity=starting_entity,
            nodes=list(node_map.values())[:MAX_REPORT_GRAPH_NODES],
            relationships=list(relationships.values())[:MAX_REPORT_GRAPH_RELATIONSHIPS],
            paths=paths,
            depth=depth,
            limitations=limitations,
        )

    async def _collect_risk(
        self,
        event_id: Any,
    ) -> tuple[list[ReportFinding], ReportRiskAssessment]:
        if not isinstance(event_id, str) or not event_id:
            return [], ReportRiskAssessment(
                status="unavailable",
                source="Member 4 on-demand inference",
                limitations=["No linked event is available for the existing risk service."],
            )
        try:
            threat = await self.threats.get_threat(event_id)
        except (DetectionEngineUnavailable, DetectionInferenceError) as exc:
            logger.warning("Member 4 report inference unavailable: %s", type(exc).__name__)
            return [], ReportRiskAssessment(
                status="unavailable",
                source="Member 4 on-demand inference",
                limitations=["Member 4 inference was unavailable when the report snapshot was captured."],
            )
        if threat is None:
            return [], ReportRiskAssessment(
                status="empty",
                source="Member 4 on-demand inference",
                limitations=[
                    "No suspicious Member 4 detection was returned for the linked event; this does not establish that the event is benign."
                ],
            )

        finding = _report_finding(threat)
        risk = ReportRiskAssessment(
            status="available" if finding.risk_score is not None else "unavailable",
            score=finding.risk_score,
            classification=finding.risk_level,
            confidence=finding.confidence,
            factors=finding.explanation[:MAX_REPORT_TEXT_LIST],
            evidence_ids=[finding.evidence_id] if finding.evidence_id else [],
            source=finding.model_name or "Member 4 on-demand inference",
            limitations=finding.limitations,
        )
        return [finding], risk

    @staticmethod
    def _report_evidence(item: Any) -> ReportEvidence:
        if not isinstance(item, dict):
            raise ReportSnapshotError("Evidence returned by the backend was not a record.")
        evidence_id = safe_report_text(item.get("evidence_id"), 200)
        if not evidence_id:
            raise ReportSnapshotError("Evidence returned by the backend has no evidence ID.")
        return ReportEvidence(
            evidence_id=evidence_id,
            source_system=safe_report_text(item.get("source_system"), 200),
            source_record_id=safe_report_text(
                item.get("source_record_id") or item.get("source_event_id"),
                200,
            ),
            observed_at=safe_report_text(
                item.get("observed_at") or item.get("created_at"),
                100,
            ),
            description=safe_report_text(item.get("description")),
            is_synthetic=item.get("is_synthetic")
            if isinstance(item.get("is_synthetic"), bool)
            else None,
        )

    @staticmethod
    def _provenance(
        flags: list[bool | None],
    ) -> Literal["synthetic", "non_synthetic", "mixed", "unknown"]:
        if not flags or any(flag is None for flag in flags):
            return "unknown"
        distinct = set(flags)
        if distinct == {True}:
            return "synthetic"
        if distinct == {False}:
            return "non_synthetic"
        return "mixed"

    @staticmethod
    def _executive_summary(
        investigation: ReportInvestigation,
        findings: list[ReportFinding],
        risk: ReportRiskAssessment,
        graph: ReportGraph,
        evidence: list[Any],
        provenance: str,
    ) -> str:
        score = (
            f"The existing Member 4 assessment returned {risk.score:g} "
            f"({risk.classification or 'classification unavailable'})."
            if risk.score is not None
            else "An existing risk score was unavailable."
        )
        provenance_text = {
            "synthetic": "The captured records are marked synthetic/demo.",
            "non_synthetic": "The captured records are not marked synthetic; this does not confirm malicious activity.",
            "mixed": "The captured records contain mixed synthetic and non-synthetic provenance.",
            "unknown": "Provenance is missing or incomplete for one or more captured records.",
        }[provenance]
        return (
            f"Investigation {investigation.id} ({investigation.title}) is "
            f"{investigation.status or 'status unavailable'}. The snapshot contains "
            f"{len(findings)} returned detection finding(s), "
            f"{len(evidence)} evidence record(s), "
            f"{len(graph.nodes)} graph entity record(s), and "
            f"{len(graph.relationships)} graph relationship(s). {score} "
            f"{provenance_text} Automated results are analyst leads, not proof of compromise."
        )

    @staticmethod
    def _unique_texts(values: list[str], limit: int) -> list[str]:
        return list(dict.fromkeys(values))[:limit]

    @staticmethod
    def _snapshot_hash(snapshot: InvestigationReportSnapshot) -> str:
        return hashlib.sha256(snapshot.model_dump_json().encode("utf-8")).hexdigest()

    @staticmethod
    def _dump(value: dict[str, Any]) -> str:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
