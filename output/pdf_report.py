from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.pdfencrypt import StandardEncryption

from engine.models import AuditReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: colors.HexColor("#DC2626"),
    Severity.HIGH: colors.HexColor("#EA580C"),
    Severity.MEDIUM: colors.HexColor("#CA8A04"),
    Severity.LOW: colors.HexColor("#2563EB"),
    Severity.INFO: colors.HexColor("#6B7280"),
}

SEVERITY_BG = {
    Severity.CRITICAL: colors.HexColor("#FEE2E2"),
    Severity.HIGH: colors.HexColor("#FFEDD5"),
    Severity.MEDIUM: colors.HexColor("#FEF9C3"),
    Severity.LOW: colors.HexColor("#DBEAFE"),
    Severity.INFO: colors.HexColor("#F3F4F6"),
}

LABELS = {
    "cover_title": "GPO Security Audit Report",
    "domain": "Domain",
    "scan_date": "Scan Date",
    "total_gpos": "Total GPOs Analyzed",
    "risk_score": "Overall Risk Score",
    "exec_summary": "Executive Summary",
    "severity": "Severity",
    "count": "Count",
    "total_findings": "Total Findings",
    "top_critical": "Top Critical & High Findings",
    "findings_summary": "Findings Summary",
    "col_id": "ID",
    "col_severity": "Severity",
    "col_gpo": "GPO",
    "col_title": "Title",
    "detailed_findings": "Detailed Findings",
    "gpo": "GPO:",
    "category": "Category:",
    "setting_path": "Setting Path:",
    "current_value": "Current Value:",
    "expected_value": "Expected Value:",
    "applies_to": "Applies To:",
    "fix_strategy": "Fix Strategy:",
    "description": "Description",
    "risk": "Risk:",
    "recommendation": "Recommendation:",
    "appendix": "Appendix: GPO Inventory",
    "col_gpo_name": "GPO Name",
    "col_status": "Status",
    "col_links": "Links",
    "col_modified": "Modified",
    "footer": "GPO Security Auditor | Created by NordicWolfSlaya1337 (Benji Ender)",
}


def generate_pdf(report: AuditReport, output_path: str, password: str):
    L = LABELS

    enc = StandardEncryption(password, ownerPassword=password, strength=128)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        encrypt=enc,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        title=f"GPO Security Audit - {report.domain}",
        author="NordicWolfSlaya1337 (Benji Ender)",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "CoverTitle", parent=styles["Title"], fontSize=28, spaceAfter=10,
        textColor=colors.HexColor("#1E293B"), alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "CoverSub", parent=styles["Normal"], fontSize=14, spaceAfter=6,
        textColor=colors.HexColor("#475569"), alignment=TA_CENTER,
        fontName="Helvetica",
    ))
    styles.add(ParagraphStyle(
        "SectionTitle", parent=styles["Heading1"], fontSize=18, spaceBefore=12,
        spaceAfter=8, textColor=colors.HexColor("#1E293B"),
        alignment=TA_LEFT, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "SubSection", parent=styles["Heading2"], fontSize=14, spaceBefore=8,
        spaceAfter=6, textColor=colors.HexColor("#334155"),
        alignment=TA_LEFT, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "BodyText2", parent=styles["Normal"], fontSize=10, spaceAfter=4,
        leading=14, alignment=TA_JUSTIFY, fontName="Helvetica",
    ))
    styles.add(ParagraphStyle(
        "FindingTitle", parent=styles["Heading2"], fontSize=14, spaceBefore=4,
        spaceAfter=6, textColor=colors.HexColor("#1E293B"),
        alignment=TA_LEFT, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "Label", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#64748B"),
        spaceAfter=2, fontName="Helvetica",
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        "SmallText", parent=styles["Normal"], fontSize=8,
        textColor=colors.HexColor("#94A3B8"), fontName="Helvetica",
        alignment=TA_LEFT,
    ))

    story = []

    # === COVER PAGE ===
    story.append(Spacer(1, 80))
    story.append(Paragraph(L["cover_title"], styles["CoverTitle"]))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="60%", thickness=2, color=colors.HexColor("#3B82F6")))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"{L['domain']}: {report.domain}", styles["CoverSub"]))
    story.append(Paragraph(f"{L['scan_date']}: {report.scan_time.strftime('%Y-%m-%d %H:%M UTC')}", styles["CoverSub"]))
    story.append(Paragraph(f"{L['total_gpos']}: {report.total_gpos}", styles["CoverSub"]))
    story.append(Paragraph("Author: NordicWolfSlaya1337 (Benji Ender)", styles["CoverSub"]))
    story.append(Spacer(1, 40))

    # Risk score
    score = report.risk_score
    score_color = (
        colors.HexColor("#DC2626") if score < 40 else
        colors.HexColor("#EA580C") if score < 60 else
        colors.HexColor("#CA8A04") if score < 80 else
        colors.HexColor("#16A34A")
    )
    story.append(Paragraph(L["risk_score"], styles["CoverSub"]))
    story.append(Spacer(1, 8))
    score_table = Table(
        [[Paragraph(f"<font size='36' color='{score_color}'><b>{score}/100</b></font>", styles["CoverSub"])]],
        colWidths=[200],
    )
    score_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 2, score_color),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    score_table.hAlign = "CENTER"
    story.append(score_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<b>{report.risk_label}</b>", styles["CoverSub"]))
    story.append(PageBreak())

    # === EXECUTIVE SUMMARY ===
    story.append(Paragraph(L["exec_summary"], styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    story.append(Spacer(1, 10))

    counts = report.severity_counts
    summary_data = [
        [L["severity"], L["count"]],
        ["Critical", str(counts.get(Severity.CRITICAL, 0))],
        ["High", str(counts.get(Severity.HIGH, 0))],
        ["Medium", str(counts.get(Severity.MEDIUM, 0))],
        ["Low", str(counts.get(Severity.LOW, 0))],
        ["Info", str(counts.get(Severity.INFO, 0))],
        [L["total_findings"], str(len(report.findings))],
    ]
    sum_widths = [200, 100]

    summary_table = Table(summary_data, colWidths=sum_widths)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("BACKGROUND", (0, 1), (-1, 1), SEVERITY_BG[Severity.CRITICAL]),
        ("BACKGROUND", (0, 2), (-1, 2), SEVERITY_BG[Severity.HIGH]),
        ("BACKGROUND", (0, 3), (-1, 3), SEVERITY_BG[Severity.MEDIUM]),
        ("BACKGROUND", (0, 4), (-1, 4), SEVERITY_BG[Severity.LOW]),
        ("BACKGROUND", (0, 5), (-1, 5), SEVERITY_BG[Severity.INFO]),
        ("BACKGROUND", (0, 6), (-1, -1), colors.HexColor("#F1F5F9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Top critical findings
    critical_findings = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if critical_findings:
        story.append(Paragraph(L["top_critical"], styles["SubSection"]))
        for f in critical_findings[:10]:
            sev_color = SEVERITY_COLORS[f.severity]
            story.append(Paragraph(
                f"<font color='{sev_color}'><b>[{f.severity.value}]</b></font> "
                f"<b>{_escape(f.title)}</b> - {_escape(f.gpo_name)}",
                styles["BodyText2"],
            ))
    story.append(PageBreak())

    # === FINDINGS SUMMARY TABLE ===
    story.append(Paragraph(L["findings_summary"], styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    story.append(Spacer(1, 10))

    if report.findings:
        page_width = A4[0] - 30 * mm
        headers = [L["col_id"], L["col_severity"], L["col_gpo"], L["col_title"]]
        col_widths = [50, 55, page_width * 0.25, page_width * 0.55 - 105]

        table_data = [headers]
        for f in report.findings:
            row = [
                f.rule_id,
                f.severity.value,
                _truncate(f.gpo_name, 25),
                _truncate(f.title, 50),
            ]
            table_data.append(row)

        findings_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i, f in enumerate(report.findings, 1):
            table_style.append(("TEXTCOLOR", (1, i), (1, i), SEVERITY_COLORS[f.severity]))
            table_style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
            if i % 2 == 0:
                table_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F8FAFC")))

        findings_table.setStyle(TableStyle(table_style))
        story.append(findings_table)
    story.append(PageBreak())

    # === DETAILED FINDINGS ===
    story.append(Paragraph(L["detailed_findings"], styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))

    for i, f in enumerate(report.findings):
        if i > 0 and i % 2 == 0:
            story.append(PageBreak())

        story.append(Spacer(1, 12))
        sev_color = SEVERITY_COLORS[f.severity]
        sev_bg = SEVERITY_BG[f.severity]

        # Severity badge + title
        badge = Table(
            [[Paragraph(f"<font color='white'><b>{f.severity.value.upper()}</b></font>",
                        ParagraphStyle("badge", fontSize=9, alignment=TA_CENTER,
                                       textColor=colors.white, fontName="Helvetica-Bold"))]],
            colWidths=[70], rowHeights=[20],
        )
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), sev_color),
            ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (0, 0), 4),
            ("RIGHTPADDING", (0, 0), (0, 0), 4),
            ("TOPPADDING", (0, 0), (0, 0), 3),
            ("BOTTOMPADDING", (0, 0), (0, 0), 3),
        ]))
        story.append(badge)
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"<b>{_escape(f.rule_id)}: {_escape(f.title)}</b>", styles["FindingTitle"]))

        # Details table
        label_col_w = 100
        value_col_w = 400
        detail_rows = [
            (L["gpo"], f.gpo_name),
            (L["category"], f.category),
        ]
        if f.setting_path:
            detail_rows.append((L["setting_path"], f.setting_path))
        if f.current_value:
            detail_rows.append((L["current_value"], f.current_value))
        if f.expected_value:
            detail_rows.append((L["expected_value"], f.expected_value))
        if f.applies_to:
            detail_rows.append((L["applies_to"], f.applies_to))
        if f.architecture_fix:
            detail_rows.append((L["fix_strategy"], f.architecture_fix))

        detail_data = []
        for label_text, value_text in detail_rows:
            is_cv = label_text == L["current_value"]
            is_ev = label_text == L["expected_value"]
            is_sp = label_text == L["setting_path"]
            val_str = _escape(value_text)
            if is_cv:
                val_str = f"<font color='#DC2626'>{val_str}</font>"
            elif is_ev:
                val_str = f"<font color='#16A34A'>{val_str}</font>"
            elif is_sp:
                val_str = f"<font color='#3B82F6'>{val_str}</font>"

            label_p = Paragraph(f"<b>{label_text}</b>", styles["Label"])
            value_p = Paragraph(val_str, styles["BodyText2"])
            detail_data.append([label_p, value_p])

        det_widths = [label_col_w, value_col_w]

        detail_table = Table(detail_data, colWidths=det_widths)
        detail_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(detail_table)
        story.append(Spacer(1, 8))

        # Description
        story.append(Paragraph(f"<b>{L['description']}</b>", styles["Label"]))
        story.append(Paragraph(_escape(f.description), styles["BodyText2"]))
        story.append(Spacer(1, 6))

        # Risk
        risk_table = Table(
            [[Paragraph(f"<b>{L['risk']}</b> {_escape(f.risk)}", styles["BodyText2"])]],
            colWidths=[500],
        )
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), sev_bg),
            ("LEFTPADDING", (0, 0), (0, 0), 8),
            ("RIGHTPADDING", (0, 0), (0, 0), 8),
            ("TOPPADDING", (0, 0), (0, 0), 6),
            ("BOTTOMPADDING", (0, 0), (0, 0), 6),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 6))

        # Recommendation
        rec_table = Table(
            [[Paragraph(f"<b>{L['recommendation']}</b> {_escape(f.recommendation)}", styles["BodyText2"])]],
            colWidths=[500],
        )
        rec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#F0FDF4")),
            ("LEFTPADDING", (0, 0), (0, 0), 8),
            ("RIGHTPADDING", (0, 0), (0, 0), 8),
            ("TOPPADDING", (0, 0), (0, 0), 6),
            ("BOTTOMPADDING", (0, 0), (0, 0), 6),
            ("BOX", (0, 0), (0, 0), 1, colors.HexColor("#86EFAC")),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 4))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))

    # === APPENDIX: GPO INVENTORY ===
    story.append(PageBreak())
    story.append(Paragraph(L["appendix"], styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    story.append(Spacer(1, 10))

    inv_headers = [L["col_gpo_name"], L["col_status"], L["col_links"], L["col_modified"]]
    inv_widths = [130, 90, 180, 65]

    inv_data = [inv_headers]
    for g in sorted(report.gpos, key=lambda x: x.name.lower()):
        links_str = ", ".join(l.som_path for l in g.links if l.enabled)[:50]
        modified = g.modified_time.strftime("%Y-%m-%d") if g.modified_time else "N/A"
        row = [
            _truncate(g.name, 30),
            g.gpo_status[:20] if g.gpo_status else "N/A",
            _truncate(links_str, 35) or "Unlinked",
            modified,
        ]
        inv_data.append(row)

    inv_table = Table(inv_data, colWidths=inv_widths, repeatRows=1)
    inv_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i in range(1, len(inv_data)):
        if i % 2 == 0:
            inv_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F8FAFC")))
    inv_table.setStyle(TableStyle(inv_style))
    story.append(inv_table)

    # Footer
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    story.append(Paragraph(
        f"{L['footer']} | {report.scan_time.strftime('%Y-%m-%d %H:%M UTC')}",
        styles["SmallText"],
    ))

    doc.build(story)


def _escape(text: str) -> str:
    """Escape XML/HTML special characters for ReportLab Paragraphs."""
    if not text:
        return ""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _truncate(text: str, max_len: int) -> str:
    if not text:
        return ""
    if len(text) > max_len:
        return text[:max_len - 3] + "..."
    return text
