from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from ..database import queries
from ..database.neo4j_connection import Neo4jConnection
from ..schemas.report_snapshot_schema import InvestigationReportSnapshot
from ..utils.serialization import serialize_neo4j_value
from .graph_service import GraphService
from .investigation_service import InvestigationNotFound, InvestigationService
from .member4_detection import (
    DetectionEngineUnavailable,
    DetectionInferenceError,
    Member4DetectionEngine,
)
from .threat_service import ThreatService

class ReportSnapshotError(Exception):
    pass


class ReportSnapshotNotFound(LookupError, ReportSnapshotError):
    pass


class ReportSnapshotTooLarge(ValueError, ReportSnapshotError):
    pass


class ReportSnapshotDataError(RuntimeError, ReportSnapshotError):
    pass


def safe_report_text(value: Any, limit: int = 4_000) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) > limit:
        text = text[: limit - 11] + "...[truncated]"
    return text if text else None


class ReportDataService:
    MAX_EVIDENCE = 100
    MAX_GRAPH_ENTITIES = 20
    GRAPH_PATH_LIMIT = 10
    MAX_TEXT_LENGTH = 4_000
    MAX_SNAPSHOT_BYTES = 1_000_000
    SCHEMA_VERSION = "1.0"
    GRAPH_INTERPRETATION = (
        "Graph relationships show potential exposure and are not proof of "
        "attacker movement or compromise."
    )

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
        self.max_graph_depth = max_graph_depth

    async def create_snapshot(
        self,
        investigation_id: str,
    ) -> InvestigationReportSnapshot:
        investigation = await self.investigations.get_investigation(
            investigation_id
        )
        limitations = [
            "External threat-intelligence providers are not implemented.",
            "An AI explanation service is not implemented.",
            self.GRAPH_INTERPRETATION,
        ]
        partial = True
        findings: list[dict[str, Any]] = []
        risk = self._empty_risk_assessment()
        evidence, evidence_truncated = await self._load_evidence(investigation)
        if evidence_truncated:
            partial = True
            limitations.append(
                "Some linked evidence records were missing or omitted by the result limit."
            )

        graph, graph_partial = await self._load_graph(investigation)
        partial = partial or graph_partial
        if graph_partial:
            limitations.append(
                f"Graph data was limited to {self.MAX_GRAPH_ENTITIES} linked entities "
                f"and {self.GRAPH_PATH_LIMIT} paths per entity."
            )

        event_id = investigation.get("related_event_id")
        if event_id:
            try:
                assessment = await self.threats.analyze_event(str(event_id))
            except DetectionEngineUnavailable:
                risk = self._unavailable_risk(
                    "Member 4 model artifacts or dependencies are unavailable."
                )
                partial = True
                limitations.append("Member 4 event assessment is unavailable.")
            except DetectionInferenceError:
                risk = self._unavailable_risk(
                    "Member 4 inference could not complete."
                )
                partial = True
                limitations.append("Member 4 event assessment failed.")
            else:
                if assessment is None:
                    risk = self._insufficient_risk(
                        "The investigation's linked event was not found."
                    )
                    partial = True
                    limitations.append(
                        "The investigation's linked event was not found during snapshot capture."
                    )
                else:
                    finding = self._finding_from_assessment(assessment)
                    findings.append(finding)
                    if finding["score"] is None or finding["risk_level"] is None:
                        risk = self._insufficient_risk(
                            "Member 4 did not return a complete investigation-priority assessment."
                        )
                        partial = True
                    else:
                        risk = {
                            "status": "completed",
                            "score": finding["score"],
                            "level": finding["risk_level"],
                            "score_kind": "member4_investigation_priority",
                            "model_name": finding["model_name"],
                            "model_version": finding["model_version"],
                            "evidence_ids": finding["evidence_ids"],
                            "warnings": finding["limitations"],
                        }
        else:
            risk = self._insufficient_risk(
                "No alert event is linked to this investigation."
            )
            limitations.append(
                "No linked alert event was available for Member 4 assessment."
            )

        if graph["status"] in {"partial", "unavailable"}:
            partial = True
        if graph["warnings"]:
            limitations.extend(graph["warnings"])

        if any(self._contains_synthetic(value) for value in (investigation, evidence, graph, findings)):
            limitations.append("This snapshot contains synthetic fixture data.")

        evidence_ids = list(dict.fromkeys(
            [
                *(
                    item
                    for item in investigation.get("evidence_ids", [])
                    if isinstance(item, str)
                ),
                *(
                    item
                    for finding in findings
                    for item in finding["evidence_ids"]
                ),
            ]
        ))
        captured_at = self._now()
        report_id = f"RPT-{uuid4().hex}"
        payload = {
            "investigation": {
                "id": investigation["id"],
                "title": investigation.get("title", ""),
                "status": investigation.get("status", "UNKNOWN"),
                "alert_id": investigation.get("related_event_id"),
                "entity_ids": investigation.get("entity_ids", []),
                "evidence_ids": investigation.get("evidence_ids", []),
                "created_at": investigation.get("created_at"),
                "updated_at": investigation.get("updated_at"),
                "is_synthetic": bool(investigation.get("is_synthetic", False)),
            },
            "executive_summary": {
                "status": "partial" if partial else "completed",
                "text": self._executive_summary(investigation, findings, risk),
                "evidence_ids": evidence_ids,
            },
            "findings": findings,
            "risk_assessment": risk,
            "threat_intelligence": {
                "status": "not_implemented",
                "providers": [],
                "findings": [],
                "warnings": [
                    "No external threat-intelligence provider is configured."
                ],
            },
            "graph": graph,
            "ai_explanation": {
                "status": "not_implemented",
                "summary": None,
                "evidence_ids": [],
                "limitations": [
                    "No AI explanation service is implemented in this backend."
                ],
            },
            "evidence": evidence,
            "provenance": {
                "sources": [
                    "investigation_service",
                    "graph_service",
                    *(
                        ["member4_detection"]
                        if findings
                        else []
                    ),
                ],
                "is_synthetic": any(
                    self._contains_synthetic(value)
                    for value in (investigation, evidence, graph, findings)
                ),
            },
            "limitations": list(dict.fromkeys(limitations)),
            "partial": partial,
            "report_id": report_id,
            "snapshot_captured_at": captured_at,
            "schema_version": self.SCHEMA_VERSION,
        }

        truncation_state = [False]
        payload = self._bound_strings(payload, truncation_state)
        if truncation_state[0]:
            payload["limitations"].append(
                f"Text fields longer than {self.MAX_TEXT_LENGTH} characters were truncated."
            )
            payload["partial"] = True
            payload["executive_summary"]["status"] = "partial"

        try:
            snapshot = InvestigationReportSnapshot.model_validate(payload)
            payload_json = json.dumps(
                snapshot.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise ReportSnapshotDataError(
                "Report snapshot data could not be validated or serialized."
            ) from exc

        if len(payload_json.encode("utf-8")) > self.MAX_SNAPSHOT_BYTES:
            raise ReportSnapshotTooLarge(
                f"Report snapshot exceeds the {self.MAX_SNAPSHOT_BYTES}-byte limit."
            )

        rows = await self.database.execute_write(
            queries.REPORT_SNAPSHOT_CREATE,
            parameters={
                "investigation_id": investigation_id,
                "report_id": report_id,
                "payload_json": payload_json,
                "schema_version": self.SCHEMA_VERSION,
                "snapshot_captured_at": captured_at,
            },
        )
        if not rows or rows[0].get("report_snapshot") is None:
            raise InvestigationNotFound(investigation_id)
        return snapshot

    async def get_snapshot(
        self,
        investigation_id: str,
        report_id: str,
    ) -> InvestigationReportSnapshot:
        rows = await self.database.execute_read(
            queries.REPORT_SNAPSHOT_GET,
            parameters={
                "investigation_id": investigation_id,
                "report_id": report_id,
            },
        )
        if not rows or rows[0].get("report_snapshot") is None:
            raise ReportSnapshotNotFound(report_id)

        payload_json = rows[0]["report_snapshot"].get("payload_json")
        if not isinstance(payload_json, str):
            raise ReportSnapshotDataError(
                "Stored report snapshot has no valid serialized payload."
            )
        try:
            return InvestigationReportSnapshot.model_validate_json(payload_json)
        except (ValidationError, ValueError) as exc:
            raise ReportSnapshotDataError(
                "Stored report snapshot is malformed."
            ) from exc

    async def _load_evidence(
        self,
        investigation: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], bool]:
        evidence_ids = investigation.get("evidence_ids", [])
        if not isinstance(evidence_ids, list) or not evidence_ids:
            return [], False
        rows = await self.database.execute_read(
            queries.REPORT_SNAPSHOT_EVIDENCE,
            parameters={
                "evidence_ids": evidence_ids,
                "limit": self.MAX_EVIDENCE + 1,
            },
        )
        evidence = [
            serialize_neo4j_value(row["evidence"])
            for row in rows
            if isinstance(row.get("evidence"), dict)
        ]
        returned_ids = {
            item.get("evidence_id")
            for item in evidence
            if isinstance(item.get("evidence_id"), str)
        }
        truncated = (
            len(evidence) > self.MAX_EVIDENCE
            or not set(evidence_ids).issubset(returned_ids)
        )
        return evidence[:self.MAX_EVIDENCE], truncated

    async def _load_graph(
        self,
        investigation: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        entity_ids = investigation.get("entity_ids", [])
        if not isinstance(entity_ids, list) or not entity_ids:
            return {
                "status": "not_applicable",
                "subgraphs": [],
                "warnings": ["No entities are linked to this investigation."],
                "interpretation": self.GRAPH_INTERPRETATION,
            }, False

        selected_ids = entity_ids[:self.MAX_GRAPH_ENTITIES]
        omitted = len(entity_ids) > len(selected_ids)
        subgraphs = []
        warnings = []
        for entity_id in selected_ids:
            subgraph = await self.graph.get_subgraph(
                entity_id=entity_id,
                depth=min(2, self.max_graph_depth),
                limit=self.GRAPH_PATH_LIMIT,
            )
            if subgraph is None:
                warnings.append(
                    f"No graph record was returned for linked entity {entity_id}."
                )
                continue
            if subgraph.get("may_be_truncated"):
                warnings.append(
                    f"Graph paths for linked entity {entity_id} reached the result limit."
                )
            subgraphs.append({
                "entity_id": entity_id,
                "subgraph": subgraph,
            })

        if omitted:
            warnings.append(
                f"Only the first {self.MAX_GRAPH_ENTITIES} linked entities were included."
            )
        status = "partial" if warnings else "completed"
        return {
            "status": status,
            "subgraphs": subgraphs,
            "warnings": warnings,
            "interpretation": self.GRAPH_INTERPRETATION,
        }, bool(warnings)

    @staticmethod
    def _finding_from_assessment(assessment: dict[str, Any]) -> dict[str, Any]:
        event_id = assessment["event_id"]
        evidence_id = assessment.get("evidence_id")
        evidence_ids = [evidence_id] if isinstance(evidence_id, str) else []
        prediction = assessment.get("prediction")
        return {
            "finding_id": event_id,
            "finding_type": "member4_model_assessment",
            "event_id": event_id,
            "event_type": assessment.get("event_type"),
            "event_time": assessment.get("event_time"),
            "severity": assessment.get("severity"),
            "description": assessment.get("description"),
            "source_evidence_status": assessment.get("source_evidence_status"),
            "model_generated_signal": assessment.get("evidence_status"),
            "prediction": (
                str(prediction) if prediction is not None else None
            ),
            "model_name": assessment.get("model_name"),
            "model_version": assessment.get("model_version"),
            "confidence": assessment.get("confidence"),
            "score": assessment.get("risk_score"),
            "risk_level": assessment.get("risk_level"),
            "evidence_ids": evidence_ids,
            "limitations": assessment.get("limitations", []),
        }

    @staticmethod
    def _empty_risk_assessment() -> dict[str, Any]:
        return {
            "status": "insufficient_evidence",
            "score": None,
            "level": None,
            "score_kind": None,
            "model_name": None,
            "model_version": None,
            "evidence_ids": [],
            "warnings": ["No risk assessment was produced."],
        }

    @classmethod
    def _insufficient_risk(cls, warning: str) -> dict[str, Any]:
        risk = cls._empty_risk_assessment()
        risk["warnings"] = [warning]
        return risk

    @classmethod
    def _unavailable_risk(cls, warning: str) -> dict[str, Any]:
        risk = cls._empty_risk_assessment()
        risk["status"] = "unavailable"
        risk["warnings"] = [warning]
        return risk

    @staticmethod
    def _executive_summary(
        investigation: dict[str, Any],
        findings: list[dict[str, Any]],
        risk: dict[str, Any],
    ) -> str:
        summary = (
            f"Investigation {investigation['id']} ({investigation.get('title', '')}) "
            f"is {investigation.get('status', 'UNKNOWN')} with "
            f"{len(investigation.get('entity_ids', []))} linked entities."
        )
        if findings:
            summary += (
                f" Member 4 assessed linked event {findings[0]['event_id']}; "
                f"the investigation-priority assessment is {risk.get('level') or 'unclassified'}."
            )
        else:
            summary += " No Member 4 event assessment is available."
        return summary

    @classmethod
    def _bound_strings(
        cls,
        value: Any,
        truncated: list[bool],
        key: str | None = None,
    ) -> Any:
        if isinstance(value, dict):
            return {
                name: cls._bound_strings(item, truncated, str(name))
                for name, item in value.items()
            }
        if isinstance(value, list):
            return [
                cls._bound_strings(item, truncated, key)
                for item in value
            ]
        if isinstance(value, str) and len(value) > cls.MAX_TEXT_LENGTH:
            if key in {
                "id",
                "report_id",
                "evidence_id",
                "evidence_ids",
                "event_id",
                "entity_id",
                "entity_ids",
                "investigation_id",
                "alert_id",
                "source_id",
                "target_id",
            } or (key is not None and key.endswith("_id")):
                raise ReportSnapshotTooLarge(
                    "A report snapshot identifier exceeds the supported text limit."
                )
            truncated[0] = True
            suffix = "...[truncated]"
            return value[:cls.MAX_TEXT_LENGTH - len(suffix)] + suffix
        return value

    @staticmethod
    def _contains_synthetic(value: Any) -> bool:
        if isinstance(value, dict):
            return value.get("is_synthetic") is True or any(
                ReportDataService._contains_synthetic(item)
                for item in value.values()
            )
        if isinstance(value, list):
            return any(
                ReportDataService._contains_synthetic(item)
                for item in value
            )
        return False

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
