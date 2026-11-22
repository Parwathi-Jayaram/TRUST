from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


SectionStatus = Literal[
    "completed",
    "partial",
    "unavailable",
    "not_implemented",
    "not_applicable",
    "insufficient_evidence",
]


class ReportInvestigation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    status: str
    alert_id: str | None
    entity_ids: list[str]
    evidence_ids: list[str]
    created_at: str | None
    updated_at: str | None
    is_synthetic: bool


class ReportExecutiveSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SectionStatus
    text: str
    evidence_ids: list[str]


class ReportFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    finding_type: str
    event_id: str
    event_type: str | None
    event_time: str | None
    severity: str | None
    description: str | None
    source_evidence_status: str | None
    model_generated_signal: str | None
    prediction: str | None
    model_name: str | None
    model_version: str | None
    confidence: float | None
    score: float | None
    risk_level: str | None
    evidence_ids: list[str]
    limitations: list[str]


class ReportRiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SectionStatus
    score: float | None
    level: str | None
    score_kind: str | None
    model_name: str | None
    model_version: str | None
    evidence_ids: list[str]
    warnings: list[str]


class ReportThreatIntelligence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SectionStatus
    providers: list[str]
    findings: list[dict[str, Any]]
    warnings: list[str]


class ReportGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SectionStatus
    subgraphs: list[dict[str, Any]]
    warnings: list[str]
    interpretation: str


class ReportAIExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SectionStatus
    summary: str | None
    evidence_ids: list[str]
    limitations: list[str]


class ReportProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[str]
    is_synthetic: bool


class InvestigationReportSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation: ReportInvestigation
    executive_summary: ReportExecutiveSummary
    findings: list[ReportFinding]
    risk_assessment: ReportRiskAssessment
    threat_intelligence: ReportThreatIntelligence
    graph: ReportGraph
    ai_explanation: ReportAIExplanation
    evidence: list[dict[str, Any]]
    provenance: ReportProvenance
    limitations: list[str]
    partial: bool
    report_id: str
    snapshot_captured_at: str
    schema_version: str
