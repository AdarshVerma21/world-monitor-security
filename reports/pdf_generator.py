"""
World Monitor Security
PDF Report Generator

Generates a professional security assessment PDF from the
assessment dictionary returned by the scanner.
"""

from __future__ import annotations

from io import BytesIO
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)


# ============================================================
# COLORS
# ============================================================

BG = colors.HexColor("#07100C")
CARD = colors.HexColor("#0D1813")
CARD_ALT = colors.HexColor("#111E18")
BORDER = colors.HexColor("#1D4032")

WHITE = colors.HexColor("#F5F7F6")
MUTED = colors.HexColor("#91A59C")

GREEN = colors.HexColor("#20F58A")
RED = colors.HexColor("#FF4D5A")
ORANGE = colors.HexColor("#FF9D45")
YELLOW = colors.HexColor("#FFD34D")
BLUE = colors.HexColor("#4DB3FF")


# ============================================================
# SAFE HELPERS
# ============================================================

def safe_dict(value: Any) -> dict:
    """Return value as dict or an empty dict."""
    return value if isinstance(value, dict) else {}


def safe_list(value: Any) -> list:
    """Return value as list or an empty list."""
    return value if isinstance(value, list) else []


def safe_str(value: Any, default: str = "N/A") -> str:
    """Convert value to readable text."""
    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return str(value)

    text = str(value).strip()

    return text if text else default


def severity_color(severity: str):
    """Return color for severity."""
    value = safe_str(severity, "").lower()

    if value == "critical":
        return RED

    if value == "high":
        return colors.HexColor("#FF5968")

    if value == "medium":
        return ORANGE

    if value == "low":
        return YELLOW

    return MUTED


def risk_rating(score: int) -> str:
    """Convert score to risk rating."""
    if score >= 15:
        return "Critical"

    if score >= 10:
        return "High"

    if score >= 5:
        return "Medium"

    return "Low"


# ============================================================
# PAGE HEADER / FOOTER
# ============================================================

def draw_page(canvas, document):
    """Draw PDF background, header and footer."""

    canvas.saveState()

    width, height = A4

    # Background
    canvas.setFillColor(BG)
    canvas.rect(
        0,
        0,
        width,
        height,
        stroke=0,
        fill=1,
    )

    # Header line
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.7)
    canvas.line(
        18 * mm,
        height - 18 * mm,
        width - 18 * mm,
        height - 18 * mm,
    )

    # Header title
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 9)

    canvas.drawString(
        18 * mm,
        height - 14 * mm,
        "WORLD MONITOR SECURITY",
    )

    # Header status
    canvas.setFillColor(GREEN)
    canvas.setFont("Helvetica", 8)

    canvas.drawRightString(
        width - 18 * mm,
        height - 14 * mm,
        "AUTHORIZED SECURITY ASSESSMENT",
    )

    # Footer line
    canvas.setStrokeColor(BORDER)
    canvas.line(
        18 * mm,
        15 * mm,
        width - 18 * mm,
        15 * mm,
    )

    # Footer text
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)

    canvas.drawString(
        18 * mm,
        9 * mm,
        "World Monitor Security • Security Assessment Report",
    )

    canvas.drawRightString(
        width - 18 * mm,
        9 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


# ============================================================
# STYLES
# ============================================================

def build_styles():
    styles = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "WMTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=27,
            textColor=WHITE,
            alignment=TA_LEFT,
            spaceAfter=8,
        ),

        "subtitle": ParagraphStyle(
            "WMSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=MUTED,
            spaceAfter=15,
        ),

        "section": ParagraphStyle(
            "WMSection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=GREEN,
            spaceBefore=8,
            spaceAfter=9,
        ),

        "heading": ParagraphStyle(
            "WMHeading",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=WHITE,
            spaceBefore=5,
            spaceAfter=6,
        ),

        "body": ParagraphStyle(
            "WMBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=13,
            textColor=WHITE,
            spaceAfter=5,
        ),

        "muted": ParagraphStyle(
            "WMMuted",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=12,
            textColor=MUTED,
        ),

        "small": ParagraphStyle(
            "WMSmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=10,
            textColor=MUTED,
        ),

        "metric": ParagraphStyle(
            "WMMetric",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=19,
            leading=22,
            textColor=WHITE,
        ),

        "label": ParagraphStyle(
            "WMLabel",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=10,
            textColor=MUTED,
        ),

        "finding": ParagraphStyle(
            "WMFinding",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=12,
            textColor=WHITE,
        ),
    }


# ============================================================
# TABLE HELPERS
# ============================================================

def metric_card(label: str, value: str, value_color=WHITE):
    label_para = Paragraph(
        label.upper(),
        ParagraphStyle(
            "MetricLabel",
            fontName="Helvetica-Bold",
            fontSize=7,
            textColor=MUTED,
            leading=9,
        ),
    )

    value_para = Paragraph(
        f'<font color="{value_color.hexval()}">{value}</font>',
        ParagraphStyle(
            "MetricValue",
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=20,
            textColor=WHITE,
        ),
    )

    table = Table(
        [[label_para], [value_para]],
        colWidths=[43 * mm],
        rowHeights=[8 * mm, 12 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CARD),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    return table


def simple_info_table(rows):
    data = []

    for label, value in rows:
        data.append(
            [
                Paragraph(
                    safe_str(label),
                    ParagraphStyle(
                        "InfoLabel",
                        fontName="Helvetica-Bold",
                        fontSize=7,
                        textColor=MUTED,
                    ),
                ),
                Paragraph(
                    safe_str(value),
                    ParagraphStyle(
                        "InfoValue",
                        fontName="Helvetica",
                        fontSize=8,
                        textColor=WHITE,
                    ),
                ),
            ]
        )

    table = Table(
        data,
        colWidths=[45 * mm, 125 * mm],
        repeatRows=0,
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CARD),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    return table


# ============================================================
# FINDINGS
# ============================================================

def extract_findings(result: dict) -> list:
    findings = result.get("findings", [])

    if not isinstance(findings, list):
        return []

    return findings


def finding_title(finding: Any) -> str:
    if isinstance(finding, dict):
        return safe_str(
            finding.get("title")
            or finding.get("name")
            or finding.get("issue")
            or finding.get("check")
            or finding.get("id"),
            "Security Finding",
        )

    return safe_str(finding, "Security Finding")


def finding_severity(finding: Any) -> str:
    if isinstance(finding, dict):
        return safe_str(
            finding.get("severity")
            or finding.get("risk")
            or finding.get("level"),
            "Unknown",
        )

    return "Unknown"


def finding_description(finding: Any) -> str:
    if isinstance(finding, dict):
        return safe_str(
            finding.get("description")
            or finding.get("details")
            or finding.get("message")
            or finding.get("reason"),
            "No description available.",
        )

    return "No additional description available."


def finding_recommendation(finding: Any) -> str:
    if isinstance(finding, dict):
        return safe_str(
            finding.get("recommendation")
            or finding.get("remediation")
            or finding.get("solution")
            or finding.get("fix"),
            "Review and remediate this security finding.",
        )

    return "Review and remediate this security finding."


def build_finding_block(finding, number: int, styles):
    title = finding_title(finding)
    severity = finding_severity(finding)
    description = finding_description(finding)
    recommendation = finding_recommendation(finding)

    sev_color = severity_color(severity)

    title_text = (
        f'<font color="{sev_color.hexval()}">●</font> '
        f'<b>{number}. {title}</b> '
        f'<font color="{sev_color.hexval()}">— {severity}</font>'
    )

    content = [
        Paragraph(title_text, styles["heading"]),
        Paragraph(
            f"<b>Description:</b> {description}",
            styles["body"],
        ),
        Paragraph(
            f"<b>Recommendation:</b> {recommendation}",
            styles["body"],
        ),
    ]

    table = Table(
        [[content]],
        colWidths=[170 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CARD),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    return table


# ============================================================
# MODULE STATUS
# ============================================================

def module_status(result: dict, module_name: str):
    """
    Determine status from result.

    Supports several possible structures so the PDF generator
    does not crash if scanner output changes slightly.
    """

    value = result.get(module_name)

    if isinstance(value, dict):
        findings = value.get("findings")

        if isinstance(findings, list) and findings:
            return f"{len(findings)} ISSUE(S)"

        status = value.get("status")

        if status:
            return safe_str(status)

    if isinstance(value, list):
        if value:
            return f"{len(value)} ISSUE(S)"

    return "OK"


# ============================================================
# MAIN PDF GENERATOR
# ============================================================

def generate_pdf_report(result: dict) -> bytes:
    """
    Generate a PDF security assessment report.

    Parameters
    ----------
    result:
        Dictionary returned by the security scanner.

    Returns
    -------
    bytes
        PDF file contents.
    """

    # Never allow None to break the report generator.
    if not isinstance(result, dict):
        result = {}

    styles = build_styles()

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=25 * mm,
        bottomMargin=22 * mm,
        title="World Monitor Security Report",
        author="World Monitor Security",
        subject="Security Assessment",
    )

    story = []

    # --------------------------------------------------------
    # DATA
    # --------------------------------------------------------

    target = safe_str(result.get("target"), "Unknown")

    final_url = safe_str(
        result.get("final_url"),
        target,
    )

    status_code = result.get("status_code")

    if status_code is None:
        status_code = result.get("status")

    status_code_text = safe_str(
        status_code,
        "N/A",
    )

    response_time = result.get("response_time")

    if response_time is None:
        response_time = result.get("response_time_ms")

    response_time_text = (
        f"{response_time} ms"
        if response_time is not None
        else "N/A"
    )

    findings = extract_findings(result)

    # Calculate risk score.
    risk_score = result.get("risk_score")

    if risk_score is None:
        score = 0

        weights = {
            "critical": 10,
            "high": 5,
            "medium": 3,
            "low": 1,
        }

        for item in findings:
            severity = finding_severity(item).lower()
            score += weights.get(severity, 0)

        risk_score = score

    try:
        risk_score_int = int(risk_score)
    except (TypeError, ValueError):
        risk_score_int = 0

    rating = safe_str(
        result.get("risk_rating"),
        risk_rating(risk_score_int),
    )

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "🔐 WORLD MONITOR SECURITY",
            styles["title"],
        )
    )

    story.append(
        Paragraph(
            "AUTHORIZED SECURITY ASSESSMENT & CONFIGURATION ANALYSIS",
            styles["subtitle"],
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %B %Y, %H:%M:%S')}",
            styles["muted"],
        )
    )

    story.append(Spacer(1, 8 * mm))

    # --------------------------------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "SECURITY OVERVIEW",
            styles["section"],
        )
    )

    rating_color = RED

    if rating.lower() == "high":
        rating_color = ORANGE
    elif rating.lower() == "medium":
        rating_color = YELLOW
    elif rating.lower() == "low":
        rating_color = GREEN

    metrics = Table(
        [
            [
                metric_card(
                    "Risk Score",
                    str(risk_score_int),
                    rating_color,
                ),
                metric_card(
                    "Risk Rating",
                    rating,
                    rating_color,
                ),
                metric_card(
                    "Findings",
                    str(len(findings)),
                    WHITE,
                ),
            ]
        ],
        colWidths=[
            55 * mm,
            55 * mm,
            55 * mm,
        ],
    )

    metrics.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    story.append(metrics)

    story.append(Spacer(1, 8 * mm))

    # --------------------------------------------------------
    # TARGET INFORMATION
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "TARGET INTELLIGENCE",
            styles["section"],
        )
    )

    story.append(
        simple_info_table(
            [
                ("Target", target),
                ("Final URL", final_url),
                ("HTTP Status", status_code_text),
                ("Response Time", response_time_text),
            ]
        )
    )

    story.append(Spacer(1, 7 * mm))

    # --------------------------------------------------------
    # TRANSPORT SECURITY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "TRANSPORT SECURITY",
            styles["section"],
        )
    )

    is_https = target.lower().startswith("https://")

    https_status = (
        "HTTPS ENABLED"
        if is_https
        else "HTTPS NOT ENABLED"
    )

    https_color = GREEN if is_https else RED

    tls_version = result.get("tls_version")

    if tls_version is None:
        tls_version = result.get("tls", {}).get("version") if isinstance(
            result.get("tls"),
            dict,
        ) else None

    transport_table = Table(
        [
            [
                Paragraph(
                    "Transport Security",
                    styles["label"],
                ),
                Paragraph(
                    f'<font color="{https_color.hexval()}">'
                    f"<b>{https_status}</b>"
                    f"</font>",
                    styles["body"],
                ),
            ],
            [
                Paragraph(
                    "TLS Version",
                    styles["label"],
                ),
                Paragraph(
                    safe_str(tls_version, "Not available"),
                    styles["body"],
                ),
            ],
        ],
        colWidths=[45 * mm, 125 * mm],
    )

    transport_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CARD),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(transport_table)

    story.append(PageBreak())

    # --------------------------------------------------------
    # SECURITY FINDINGS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "SECURITY FINDINGS",
            styles["section"],
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No security findings were returned by the scanner.",
                styles["body"],
            )
        )
    else:
        for index, finding in enumerate(findings, start=1):
            story.append(
                KeepTogether(
                    [
                        build_finding_block(
                            finding,
                            index,
                            styles,
                        ),
                        Spacer(1, 4 * mm),
                    ]
                )
            )

    # --------------------------------------------------------
    # MODULE STATUS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "SECURITY MODULES",
            styles["section"],
        )
    )

    modules = [
        ("HTTP Headers", "http_headers"),
        ("CORS", "cors"),
        ("Cookies", "cookies"),
        ("TLS / HTTPS", "tls"),
        ("Security", "security"),
    ]

    module_rows = [
        [
            Paragraph("<b>MODULE</b>", styles["small"]),
            Paragraph("<b>STATUS</b>", styles["small"]),
        ]
    ]

    for display_name, key in modules:
        status = module_status(result, key)

        module_rows.append(
            [
                Paragraph(
                    display_name,
                    styles["body"],
                ),
                Paragraph(
                    status,
                    styles["body"],
                ),
            ]
        )

    module_table = Table(
        module_rows,
        colWidths=[90 * mm, 80 * mm],
        repeatRows=1,
    )

    module_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), CARD_ALT),
                ("BACKGROUND", (0, 1), (-1, -1), CARD),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(module_table)

    story.append(Spacer(1, 8 * mm))

    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "SECURITY RECOMMENDATIONS",
            styles["section"],
        )
    )

    recommendations = []

    for finding in findings:
        recommendation = finding_recommendation(finding)

        if recommendation not in recommendations:
            recommendations.append(recommendation)

    if not recommendations:
        recommendations = [
            "Maintain current security configuration.",
            "Regularly reassess HTTP security headers.",
            "Verify TLS configuration in production.",
            "Review CORS and cookie policies periodically.",
        ]

    recommendation_rows = []

    for index, recommendation in enumerate(
        recommendations,
        start=1,
    ):
        recommendation_rows.append(
            [
                Paragraph(
                    f"<b>{index}</b>",
                    styles["body"],
                ),
                Paragraph(
                    recommendation,
                    styles["body"],
                ),
            ]
        )

    recommendation_table = Table(
        recommendation_rows,
        colWidths=[12 * mm, 158 * mm],
    )

    recommendation_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CARD),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(recommendation_table)

    story.append(PageBreak())

    # --------------------------------------------------------
    # RAW ASSESSMENT SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "ASSESSMENT SUMMARY",
            styles["section"],
        )
    )

    summary_rows = [
        ("Target", target),
        ("Final URL", final_url),
        ("HTTP Status", status_code_text),
        ("Risk Score", str(risk_score_int)),
        ("Risk Rating", rating),
        ("Total Findings", str(len(findings))),
        ("Response Time", response_time_text),
        ("HTTPS", https_status),
    ]

    story.append(
        simple_info_table(summary_rows)
    )

    story.append(Spacer(1, 10 * mm))

    story.append(
        Paragraph(
            "AUTHORIZATION NOTICE",
            styles["section"],
        )
    )

    story.append(
        Paragraph(
            "This report is intended for authorized security "
            "assessment and configuration analysis only. "
            "Only scan systems that you own or have explicit "
            "permission to test.",
            styles["body"],
        )
    )

    story.append(Spacer(1, 15 * mm))

    story.append(
        Paragraph(
            "WORLD MONITOR SECURITY",
            ParagraphStyle(
                "FinalBrand",
                fontName="Helvetica-Bold",
                fontSize=11,
                textColor=GREEN,
                alignment=TA_CENTER,
            ),
        )
    )

    # --------------------------------------------------------
    # BUILD
    # --------------------------------------------------------

    document.build(
        story,
        onFirstPage=draw_page,
        onLaterPages=draw_page,
    )

    pdf_bytes = buffer.getvalue()

    buffer.close()

    return pdf_bytes