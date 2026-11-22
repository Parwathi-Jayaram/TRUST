from __future__ import annotations

import math
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    Flowable,
    LayoutError,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..schemas.report_schema import (
    InvestigationReportSnapshot,
    ReportEntity,
    ReportRelationship,
)
from .report_data_service import safe_report_text

MAX_REPORT_PDF_BYTES = 5_000_000
MAX_DIAGRAM_NODES = 12
MAX_DIAGRAM_RELATIONSHIPS = 20

NAVY = colors.HexColor("#101b2c")
CYAN = colors.HexColor("#087e8b")
SLATE = colors.HexColor("#475569")
LIGHT = colors.HexColor("#f1f5f9")
AMBER = colors.HexColor("#92400e")


class ReportPdfError(RuntimeError):
    pass


class ReportPdfTooLarge(ReportPdfError):
    pass


class GraphDiagram(Flowable):
    def __init__(
        self,
        nodes: list[ReportEntity],
        relationships: list[ReportRelationship],
    ):
        super().__init__()
        self.nodes = nodes[:MAX_DIAGRAM_NODES]
        self.relationships = relationships[:MAX_DIAGRAM_RELATIONSHIPS]
        self.width = 0
        self.height = 0

    def wrap(self, available_width: float, _available_height: float) -> tuple[float, float]:
        self.width = available_width
        rows = max(1, math.ceil(len(self.nodes) / 4))
        self.height = rows * 76 + 18
        return self.width, self.height

    def draw(self) -> None:
        if not self.nodes:
            return
        canvas = self.canv
        columns = min(4, len(self.nodes))
        box_width = min(132, (self.width - 24) / columns)
        box_height = 48
        gap_x = (self.width - columns * box_width) / (columns + 1)
        positions: dict[str, tuple[float, float]] = {}
        for index, node in enumerate(self.nodes):
            row, column = divmod(index, 4)
            x = gap_x + column * (box_width + gap_x)
            y = self.height - 12 - (row + 1) * 76
            positions[node.id] = (x, y)

        canvas.saveState()
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(1)
        canvas.setFont("Helvetica", 6)
        for relationship in self.relationships:
            source = positions.get(relationship.source_id)
            target = positions.get(relationship.target_id)
            if source is None or target is None:
                continue
            x1, y1 = source[0] + box_width / 2, source[1] + box_height
            x2, y2 = target[0] + box_width / 2, target[1]
            canvas.line(x1, y1, x2, y2)
            label = _pdf_text(relationship.type, 40)
            canvas.drawCentredString((x1 + x2) / 2, (y1 + y2) / 2, label)

        for node in self.nodes:
            x, y = positions[node.id]
            canvas.setFillColor(LIGHT)
            canvas.setStrokeColor(colors.HexColor("#94a3b8"))
            canvas.roundRect(x, y, box_width, box_height, 5, fill=1, stroke=1)
            title = _pdf_text(node.name or node.type or node.id, 80)
            identifier = _pdf_text(node.id, 40)
            canvas.setFillColor(NAVY)
            canvas.setFont("Helvetica-Bold", 8)
            canvas.drawCentredString(x + box_width / 2, y + 29, _fit_text(title, "Helvetica-Bold", 8, box_width - 8))
            canvas.setFillColor(SLATE)
            canvas.setFont("Helvetica", 7)
            canvas.drawCentredString(x + box_width / 2, y + 15, _fit_text(identifier, "Helvetica", 7, box_width - 8))
            canvas.setFont("Helvetica", 6)
            canvas.drawCentredString(
                x + box_width / 2,
                y + 5,
                _fit_text(node.type or "Entity", "Helvetica", 6, box_width - 8),
            )
        canvas.restoreState()


def _pdf_text(value: Any, limit: int = 4_000) -> str:
    text = safe_report_text(value, limit) or "Not available"
    return text.encode("latin-1", "replace").decode("latin-1")


def _fit_text(text: str, font: str, size: float, width: float) -> str:
    if stringWidth(text, font, size) <= width:
        return text
    while text and stringWidth(f"{text}...", font, size) > width:
        text = text[:-1]
    return f"{text}..."


def _paragraph(text: Any, style: Any, *, limit: int = 4_000) -> Paragraph:
    safe = escape(_pdf_text(text, limit)).replace("\r\n", "\n").replace("\n", "<br/>")
    return Paragraph(safe, style)


def _table(rows: list[list[Any]], widths: list[float] | None = None) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEADING", (0, 0), (-1, -1), 11),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("TEXTCOLOR", (0, 1), (-1, -1), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _header_footer(canvas, document) -> None:
    canvas.saveState()
    page_width, page_height = letter
    canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
    canvas.setLineWidth(0.5)
    canvas.line(document.leftMargin, page_height - 34, page_width - document.rightMargin, page_height - 34)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(NAVY)
    canvas.drawString(document.leftMargin, page_height - 26, "TRUSTRAIL AI | INVESTIGATION REPORT")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(SLATE)
    canvas.drawString(document.leftMargin, 22, "CONFIDENTIAL - FOR AUTHORIZED ANALYST USE")
    canvas.drawRightString(page_width - document.rightMargin, 22, f"Page {document.page}")
    canvas.restoreState()


def _section(title: str, styles) -> list[Any]:
    return [
        Paragraph(escape(title), styles["SectionHeading"]),
        Spacer(1, 7),
    ]


def render_investigation_report(
    snapshot: InvestigationReportSnapshot,
    generated_at: str,
) -> bytes:
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=30,
        textColor=NAVY,
        alignment=TA_LEFT,
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        leading=17,
        textColor=CYAN,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=NAVY,
        spaceBefore=5,
        spaceAfter=5,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=NAVY,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="ReportSmall",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=SLATE,
    ))
    styles.add(ParagraphStyle(
        name="ReportCoverLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=SLATE,
    ))
    styles.add(ParagraphStyle(
        name="ReportCoverValue",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=NAVY,
    ))
    styles.add(ParagraphStyle(
        name="ReportCenter",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=AMBER,
        alignment=TA_CENTER,
    ))

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.62 * inch,
        bottomMargin=0.55 * inch,
        title=f"TRUSTRAIL AI Investigation {snapshot.investigation.id}",
        author="TRUSTRAIL AI",
        subject="Automated investigation report",
    )
    story: list[Any] = [
        Spacer(1, 1.15 * inch),
        Paragraph("TRUSTRAIL AI", styles["ReportSubtitle"]),
        Paragraph("Cyber Threat Investigation Report", styles["ReportTitle"]),
        Paragraph("Evidence-led analyst report", styles["ReportBody"]),
        Spacer(1, 0.35 * inch),
    ]
    starting_entity = snapshot.graph.starting_entity
    entity_value = (
        f"{starting_entity.name or starting_entity.id} ({starting_entity.id})"
        if starting_entity
        else "No starting entity linked"
    )
    cover_rows = [
        [_paragraph("Investigation ID", styles["ReportCoverLabel"]), _paragraph(snapshot.investigation.id, styles["ReportCoverValue"])],
        [_paragraph("Entity type and value", styles["ReportCoverLabel"]), _paragraph(entity_value, styles["ReportCoverValue"])],
        [_paragraph("Investigation status", styles["ReportCoverLabel"]), _paragraph(snapshot.investigation.status or "Not available", styles["ReportCoverValue"])],
        [_paragraph("Snapshot captured", styles["ReportCoverLabel"]), _paragraph(snapshot.snapshot_captured_at, styles["ReportCoverValue"])],
        [_paragraph("PDF generated", styles["ReportCoverLabel"]), _paragraph(generated_at, styles["ReportCoverValue"])],
        [_paragraph("Analyst identifier", styles["ReportCoverLabel"]), _paragraph("Unavailable - shared bearer authentication has no analyst identity", styles["ReportCoverValue"])],
        [_paragraph("Data provenance", styles["ReportCoverLabel"]), _paragraph(snapshot.provenance.replace("_", " ").title(), styles["ReportCoverValue"])],
    ]
    cover = Table(cover_rows, colWidths=[1.6 * inch, 4.9 * inch], hAlign="LEFT")
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([
        cover,
        Spacer(1, 0.3 * inch),
        Paragraph("CONFIDENTIAL", styles["ReportCenter"]),
        PageBreak(),
    ])

    story.extend(_section("1. Executive summary", styles))
    story.append(_paragraph(snapshot.executive_summary, styles["ReportBody"]))
    story.append(_paragraph(
        f"Investigation purpose: {snapshot.investigation.title}",
        styles["ReportBody"],
    ))
    if snapshot.findings:
        finding_rows = [[
            _paragraph("Event", styles["ReportSmall"]),
            _paragraph("Severity / risk", styles["ReportSmall"]),
            _paragraph("Finding summary", styles["ReportSmall"]),
            _paragraph("Timestamp", styles["ReportSmall"]),
        ]]
        for finding in snapshot.findings:
            finding_rows.append([
                _paragraph(finding.event_id, styles["ReportSmall"]),
                _paragraph(
                    f"{finding.severity or 'Unavailable'} / "
                    f"{finding.risk_level or 'Unavailable'} "
                    f"({finding.risk_score if finding.risk_score is not None else 'score unavailable'})",
                    styles["ReportSmall"],
                ),
                _paragraph(finding.summary or "No summary supplied.", styles["ReportSmall"]),
                _paragraph(finding.event_time or "Not supplied", styles["ReportSmall"]),
            ])
        story.append(_table(finding_rows, [1.1 * inch, 1.2 * inch, 2.8 * inch, 1.2 * inch]))
    else:
        story.append(_paragraph("No detection finding was returned for the linked event.", styles["ReportBody"]))
    story.extend([
        Spacer(1, 8),
        _paragraph(
            "Overall assessment: automated signals and modeled graph relationships assist human review; they do not independently confirm malicious activity or compromise.",
            styles["ReportBody"],
        ),
    ])

    story.extend(_section("2. Risk assessment", styles))
    risk = snapshot.risk_assessment
    risk_rows = [
        [_paragraph("Assessment status", styles["ReportSmall"]), _paragraph(risk.status.title(), styles["ReportSmall"])],
        [_paragraph("Risk score", styles["ReportSmall"]), _paragraph(str(risk.score) if risk.score is not None else "Unavailable", styles["ReportSmall"])],
        [_paragraph("Classification", styles["ReportSmall"]), _paragraph(risk.classification or "Unavailable", styles["ReportSmall"])],
        [_paragraph("Confidence", styles["ReportSmall"]), _paragraph(str(risk.confidence) if risk.confidence is not None else "Unavailable", styles["ReportSmall"])],
        [_paragraph("Source", styles["ReportSmall"]), _paragraph(risk.source or "Unavailable", styles["ReportSmall"])],
        [_paragraph("Supporting evidence IDs", styles["ReportSmall"]), _paragraph(", ".join(risk.evidence_ids) or "None returned", styles["ReportSmall"])],
    ]
    story.append(_table(risk_rows, [1.65 * inch, 4.65 * inch]))
    story.extend(_text_list("Risk factors and supporting signals", risk.factors, styles))
    story.extend(_text_list("Risk limitations", risk.limitations, styles))

    story.extend(_section("3. Threat intelligence", styles))
    intelligence = snapshot.threat_intelligence
    story.append(_paragraph(
        f"Source: {intelligence.provider or 'Member 3 provider unavailable'} | "
        f"Status: {intelligence.status.title()}",
        styles["ReportBody"],
    ))
    story.append(_paragraph(intelligence.message, styles["ReportBody"]))
    if intelligence.findings:
        rows = [[
            _paragraph("Indicator / event", styles["ReportSmall"]),
            _paragraph("Summary", styles["ReportSmall"]),
            _paragraph("Evidence ID", styles["ReportSmall"]),
            _paragraph("Timestamp", styles["ReportSmall"]),
        ]]
        rows.extend([
            [
                _paragraph(finding.event_id, styles["ReportSmall"]),
                _paragraph(finding.summary or "Not supplied", styles["ReportSmall"]),
                _paragraph(finding.evidence_id or "Not supplied", styles["ReportSmall"]),
                _paragraph(finding.event_time or "Not supplied", styles["ReportSmall"]),
            ]
            for finding in intelligence.findings
        ])
        story.append(_table(rows, [1.4 * inch, 3.2 * inch, 1.0 * inch, 0.7 * inch]))
    else:
        story.append(_paragraph("No threat-intelligence findings are included because the provider is unavailable.", styles["ReportBody"]))
    story.extend(_text_list("Threat-intelligence limitations", intelligence.limitations, styles))

    story.extend(_section("4. Neo4j graph investigation", styles))
    graph = snapshot.graph
    story.append(_paragraph(
        f"Starting entity: {graph.starting_entity.name or graph.starting_entity.id} "
        f"({graph.starting_entity.id})" if graph.starting_entity else "Starting entity: unavailable",
        styles["ReportBody"],
    ))
    story.append(_paragraph(
        f"Graph evidence status: {graph.status.title()} | Search depth: {graph.depth} hop(s) | "
        f"{len(graph.nodes)} entities | {len(graph.relationships)} relationships",
        styles["ReportBody"],
    ))
    if graph.nodes and graph.relationships:
        story.append(GraphDiagram(graph.nodes, graph.relationships))
        story.append(Spacer(1, 8))
    if graph.relationships:
        relationship_rows = [[
            _paragraph("Source", styles["ReportSmall"]),
            _paragraph("Relationship", styles["ReportSmall"]),
            _paragraph("Target", styles["ReportSmall"]),
            _paragraph("Evidence IDs", styles["ReportSmall"]),
        ]]
        name_by_id = {node.id: node.name or node.id for node in graph.nodes}
        for relationship in graph.relationships:
            relationship_rows.append([
                _paragraph(name_by_id.get(relationship.source_id, relationship.source_id), styles["ReportSmall"]),
                _paragraph(relationship.type, styles["ReportSmall"]),
                _paragraph(name_by_id.get(relationship.target_id, relationship.target_id), styles["ReportSmall"]),
                _paragraph(", ".join(relationship.evidence_ids) or "Not supplied", styles["ReportSmall"]),
            ])
        story.append(_table(relationship_rows, [1.65 * inch, 1.5 * inch, 1.65 * inch, 1.5 * inch]))
    else:
        story.append(_paragraph(
            f"No qualifying graph relationships were returned within {graph.depth} hop(s).",
            styles["ReportBody"],
        ))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Directed paths between linked investigation entities", styles["Heading3"]))
    if graph.paths:
        for index, path in enumerate(graph.paths, start=1):
            pieces = []
            for node_index, node in enumerate(path.nodes):
                pieces.append(f"{node.name or node.id} ({node.id})")
                if node_index < len(path.relationships):
                    pieces.append(f" -[{path.relationships[node_index].type}]-> ")
            story.append(_paragraph(f"Path {index} ({path.depth} hop(s)): {''.join(pieces)}", styles["ReportBody"]))
    else:
        story.append(_paragraph(
            f"No qualifying directed path was found within the selected {graph.depth}-hop limit.",
            styles["ReportBody"],
        ))
    story.extend(_text_list("Graph limitations", graph.limitations, styles))

    story.extend(_section("5. AI explanation", styles))
    ai = snapshot.ai_explanation
    story.append(_paragraph(
        f"AI explanation status: {ai.status.title()} | Provider: {ai.provider or 'Unavailable'}",
        styles["ReportBody"],
    ))
    story.append(_paragraph(ai.message, styles["ReportBody"]))
    if ai.summary:
        story.append(_paragraph(f"Summary: {ai.summary}", styles["ReportBody"]))
    if ai.graph_interpretation:
        story.append(_paragraph(f"Graph interpretation: {ai.graph_interpretation}", styles["ReportBody"]))
    if ai.risk_explanation:
        story.append(_paragraph(f"Risk explanation: {ai.risk_explanation}", styles["ReportBody"]))
    story.extend(_text_list("Recommendations", ai.recommendations, styles))
    story.extend(_text_list("AI limitations", ai.limitations, styles))

    story.extend(_section("6. Evidence and references", styles))
    story.append(_paragraph(
        f"Snapshot retrieval time: {snapshot.snapshot_captured_at}",
        styles["ReportBody"],
    ))
    if snapshot.evidence:
        evidence_rows = [[
            _paragraph("Evidence ID", styles["ReportSmall"]),
            _paragraph("Source / record", styles["ReportSmall"]),
            _paragraph("Observed", styles["ReportSmall"]),
            _paragraph("Description", styles["ReportSmall"]),
            _paragraph("Provenance", styles["ReportSmall"]),
        ]]
        evidence_rows.extend([
            [
                _paragraph(item.evidence_id, styles["ReportSmall"]),
                _paragraph(
                    f"{item.source_system or 'Source unavailable'} / "
                    f"{item.source_record_id or 'Record unavailable'}",
                    styles["ReportSmall"],
                ),
                _paragraph(item.observed_at or "Not supplied", styles["ReportSmall"]),
                _paragraph(item.description or "No description supplied", styles["ReportSmall"]),
                _paragraph(
                    "Synthetic" if item.is_synthetic is True
                    else "Not marked synthetic" if item.is_synthetic is False
                    else "Unknown",
                    styles["ReportSmall"],
                ),
            ]
            for item in snapshot.evidence
        ])
        story.append(_table(evidence_rows, [0.85 * inch, 1.3 * inch, 0.9 * inch, 2.45 * inch, 0.95 * inch]))
    else:
        story.append(_paragraph("No evidence records were attached or returned for this snapshot.", styles["ReportBody"]))
    story.extend(_text_list("Report limitations", snapshot.limitations, styles))
    story.extend([
        Spacer(1, 8),
        _paragraph(
            "This report was generated from a bounded snapshot. Repeated downloads use that stored snapshot; they do not silently replace its evidence with newer graph data.",
            styles["ReportSmall"],
        ),
        Spacer(1, 12),
        Paragraph("7. Disclaimer", styles["SectionHeading"]),
        _paragraph(
            "Automated risk assessments, graph relationships, threat-intelligence results, and AI-generated explanations assist human analysts. They do not independently confirm malicious activity, compromise, or attacker movement. Validate source records and evidence before operational decisions.",
            styles["ReportBody"],
        ),
    ])

    try:
        document.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    except (LayoutError, OSError, UnicodeError, ValueError, TypeError) as exc:
        raise ReportPdfError("Investigation report PDF generation failed.") from exc
    result = buffer.getvalue()
    if len(result) > MAX_REPORT_PDF_BYTES:
        raise ReportPdfTooLarge("Generated report PDF exceeds the allowed size.")
    if not result.startswith(b"%PDF-"):
        raise ReportPdfError("Generated report PDF is invalid.")
    return result


def _text_list(title: str, items: list[str], styles) -> list[Any]:
    content: list[Any] = [Paragraph(escape(title), styles["Heading3"])]
    if not items:
        content.append(_paragraph("None returned.", styles["ReportSmall"]))
        return content
    for item in items:
        content.append(_paragraph(f"- {item}", styles["ReportSmall"]))
    return content
