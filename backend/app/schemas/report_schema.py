from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


SourceStatus = Literal["available", "unavailable", "empty", "partial"]


class ReportEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=200)
    name: str | None = Field(default=None, max_length=500)
    type: str | None = Field(default=None, max_length=100)
    labels: list[str] = Field(default_factory=list, max_length=10)
    criticality: str | None = Field(default=None, max_length=50)
    risk_level: str | None = Field(default=None, max_length=50)
    is_synthetic: bool | None = None


class ReportRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str | None = Field(default=None, max_length=200)
    type: str = Field(min_length=1, max_length=200)
    source_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


class ReportPath(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[ReportEntity] = Field(min_length=2, max_length=4)
    relationships: list[ReportRelationship] = Field(min_length=1, max_length=3)
    depth: int = Field(ge=1, le=3)


class ReportGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SourceStatus
    starting_entity: ReportEntity | None = None
    nodes: list[ReportEntity] = Field(default_factory=list, max_length=50)
    relationships: list[ReportRelationship] = Field(default_factory=list, max_length=100)
    paths: list[ReportPath] = Field(default_factory=list, max_length=20)
    depth: int = Field(ge=0, le=3)
    limitations: list[str] = Field(default_factory=list, max_length=20)


class ReportEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=200)
    source_system: str | None = Field(default=None, max_length=200)
    source_record_id: str | None = Field(default=None, max_length=200)
    observed_at: str | None = Field(default=None, max_length=100)
    description: str | None = Field(default=None, max_length=4000)
    is_synthetic: bool | None = None


class ReportInvestigation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=500)
    status: str | None = Field(default=None, max_length=50)
    created_at: str | None = Field(default=None, max_length=100)
    updated_at: str | None = Field(default=None, max_length=100)
    related_event_id: str | None = Field(default=None, max_length=200)
    entity_ids: list[str] = Field(default_factory=list, max_length=50)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    is_synthetic: bool | None = None


class ReportRiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SourceStatus
    score: float | None = Field(default=None, ge=0, le=100)
    classification: str | None = Field(default=None, max_length=50)
    confidence: float | None = Field(default=None, ge=0, le=1)
    factors: list[str] = Field(default_factory=list, max_length=20)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    source: str | None = Field(default=None, max_length=200)
    limitations: list[str] = Field(default_factory=list, max_length=20)


class ReportFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=200)
    event_type: str | None = Field(default=None, max_length=200)
    event_time: str | None = Field(default=None, max_length=100)
    severity: str | None = Field(default=None, max_length=50)
    summary: str | None = Field(default=None, max_length=4000)
    evidence_id: str | None = Field(default=None, max_length=200)
    risk_score: float | None = Field(default=None, ge=0, le=100)
    risk_level: str | None = Field(default=None, max_length=50)
    confidence: float | None = Field(default=None, ge=0, le=1)
    model_name: str | None = Field(default=None, max_length=200)
    model_version: str | None = Field(default=None, max_length=100)
    explanation: list[str] = Field(default_factory=list, max_length=20)
    limitations: list[str] = Field(default_factory=list, max_length=20)
    is_synthetic: bool | None = None


class ReportThreatIntelligence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SourceStatus
    provider: str | None = Field(default=None, max_length=200)
    findings: list[ReportFinding] = Field(default_factory=list, max_length=20)
    message: str = Field(max_length=1000)
    limitations: list[str] = Field(default_factory=list, max_length=20)


class ReportAIExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SourceStatus
    provider: str | None = Field(default=None, max_length=200)
    summary: str | None = Field(default=None, max_length=4000)
    graph_interpretation: str | None = Field(default=None, max_length=4000)
    risk_explanation: str | None = Field(default=None, max_length=4000)
    recommendations: list[str] = Field(default_factory=list, max_length=20)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    message: str = Field(max_length=1000)
    limitations: list[str] = Field(default_factory=list, max_length=20)


class InvestigationReportSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    report_id: str = Field(min_length=1, max_length=80)
    snapshot_captured_at: str = Field(min_length=1, max_length=100)
    investigation: ReportInvestigation
    executive_summary: str = Field(min_length=1, max_length=4000)
    findings: list[ReportFinding] = Field(default_factory=list, max_length=20)
    risk_assessment: ReportRiskAssessment
    threat_intelligence: ReportThreatIntelligence
    graph: ReportGraph
    ai_explanation: ReportAIExplanation
    evidence: list[ReportEvidence] = Field(default_factory=list, max_length=100)
    provenance: Literal["synthetic", "non_synthetic", "mixed", "unknown"]
    limitations: list[str] = Field(default_factory=list, max_length=50)
    partial: bool
