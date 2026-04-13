import io
from datetime import datetime

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _risk_color(label: str):
    normalized = str(label or "").lower()
    if any(token in normalized for token in ["critical", "high", "vulnerable"]):
        return colors.HexColor("#dc2626")
    if any(token in normalized for token in ["medium", "standard", "partial"]):
        return colors.HexColor("#f59e0b")
    if any(token in normalized for token in ["low", "secure", "pqc ready", "elite"]):
        return colors.HexColor("#16a34a")
    return colors.HexColor("#0f172a")


def _color_markup(value):
    if hasattr(value, "hexval"):
        raw = value.hexval()
        return f"#{raw[2:]}" if raw.startswith("0x") else raw
    return str(value)


def _build_kpi_table(cards):
    if not cards:
        return None

    rows = []
    for card in cards:
        rows.append([
            Paragraph(f"<b>{card['label']}</b>", getSampleStyleSheet()["BodyText"]),
            Paragraph(f"<font color='{_color_markup(card.get('color', '#0f172a'))}'><b>{card['value']}</b></font>", getSampleStyleSheet()["BodyText"]),
        ])

    table = Table(rows, colWidths=[2.7 * inch, 3.8 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def _build_bar_chart(title, labels, values, fill_color="#0050cb"):
    if not labels or not values:
        return None

    drawing = Drawing(500, 220)
    chart = VerticalBarChart()
    chart.x = 40
    chart.y = 35
    chart.height = 130
    chart.width = 400
    chart.data = [values]
    chart.categoryAxis.categoryNames = labels
    chart.barWidth = 18
    chart.groupSpacing = 14
    chart.valueAxis.valueMin = 0
    chart.valueAxis.forceZero = 1
    chart.valueAxis.labelTextFormat = "%d"
    chart.categoryAxis.labels.boxAnchor = "ne"
    chart.categoryAxis.labels.dx = -4
    chart.categoryAxis.labels.dy = -10
    chart.categoryAxis.labels.angle = 20
    chart.bars[0].fillColor = colors.HexColor(fill_color)
    chart.strokeColor = colors.HexColor(fill_color)
    drawing.add(chart)

    # Title is appended separately by the caller; keep the chart clean.
    return drawing


def _build_pie_chart(labels, values, slice_colors):
    if not labels or not values:
        return None
    if sum(values) <= 0:
        return None

    drawing = Drawing(500, 220)
    pie = Pie()
    pie.x = 155
    pie.y = 20
    pie.width = 160
    pie.height = 160
    pie.data = values
    pie.labels = labels
    pie.simpleLabels = 0
    pie.sideLabels = 1
    pie.slices.strokeWidth = 0.5

    for index, slice_color in enumerate(slice_colors):
        pie.slices[index].fillColor = colors.HexColor(slice_color)

    drawing.add(pie)
    return drawing


def _build_subdomain_table(subdomain_rows):
    if not subdomain_rows:
        return None

    table_data = [["Subdomain", "Status", "Criteria", "SSL", "TLS", "Algorithm", "Days Left"]]
    for row in subdomain_rows[:10]:
        table_data.append([
            row.get("subdomain", ""),
            row.get("status", "unknown"),
            row.get("bucket", "critical").replace("_", " "),
            row.get("ssl_rating", "N/A"),
            ", ".join(row.get("tls_versions", [])) or "N/A",
            row.get("algorithm", "N/A"),
            row.get("days_to_expiry", "N/A"),
        ])

    table = Table(table_data, repeatRows=1, colWidths=[1.6 * inch, 0.8 * inch, 0.9 * inch, 0.55 * inch, 1.2 * inch, 0.9 * inch, 0.7 * inch])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]

    for index, row in enumerate(subdomain_rows[:10], start=1):
        status = str(row.get("status", "unknown")).lower()
        bucket = str(row.get("bucket", "critical")).lower()
        row_color = colors.HexColor("#ecfdf5") if status == "active" else colors.HexColor("#fef2f2")
        style.append(("BACKGROUND", (0, index), (-1, index), row_color))
        style.append(("TEXTCOLOR", (1, index), (1, index), _risk_color(bucket)))
        style.append(("TEXTCOLOR", (2, index), (2, index), _risk_color(bucket)))

    table.setStyle(TableStyle(style))
    return table


def generate_pdf_report(data: dict) -> bytes:
    """
    Generates a richer PDF report with KPI cards, charts, subdomain detail, and color coding.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    elements = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor(data.get("theme_color", "#0050cb")),
        spaceAfter=8,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor(data.get("secondary_theme_color", "#0f172a")),
        spaceBefore=10,
        spaceAfter=6,
    )
    normal_style = styles["BodyText"]

    report_title = data.get("report_title", "Enterprise Quantum Security Report")
    elements.append(Paragraph(report_title, title_style))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 10))

    # Executive summary block
    elements.append(Paragraph("Executive Summary", heading_style))
    elements.append(Paragraph(data.get("executive_summary", "No executive summary available."), normal_style))
    elements.append(Spacer(1, 10))

    score = data.get("risk_score", 0)
    risk = data.get("overall_risk", "Unknown")
    risk_color = _risk_color(risk)

    summary_cards = data.get("summary_cards") or [
        {"label": "PQC Readiness Score", "value": f"{score}%", "color": _color_markup(risk_color)},
        {"label": "Risk Level", "value": risk, "color": _color_markup(risk_color)},
    ]
    kpi_table = _build_kpi_table(summary_cards)
    if kpi_table:
        elements.append(kpi_table)
        elements.append(Spacer(1, 12))

    chart_data = data.get("chart_data") or {}
    if chart_data:
        elements.append(Paragraph(chart_data.get("title", "Key Metrics"), heading_style))
        if chart_data.get("type") == "pie":
            drawing = _build_pie_chart(
                chart_data.get("labels", []),
                chart_data.get("values", []),
                chart_data.get("colors", ["#0f172a", "#0050cb", "#16a34a", "#f59e0b"]),
            )
        else:
            drawing = _build_bar_chart(
                chart_data.get("title", "Key Metrics"),
                chart_data.get("labels", []),
                chart_data.get("values", []),
                chart_data.get("color", "#0050cb"),
            )
        if drawing:
            elements.append(drawing)
            elements.append(Spacer(1, 10))

    # Website/subdomain section
    subdomain_rows = data.get("subdomain_rows", [])
    if subdomain_rows:
        elements.append(Paragraph("Subdomain Intelligence", heading_style))
        elements.append(Paragraph(f"Discovered subdomains: {len(subdomain_rows)}", normal_style))

        active_count = sum(1 for row in subdomain_rows if row.get("status") == "active")
        inactive_count = sum(1 for row in subdomain_rows if row.get("status") == "inactive")
        pqc_ready = sum(1 for row in subdomain_rows if str(row.get("bucket", "")).lower() == "pqc_ready")
        standard = sum(1 for row in subdomain_rows if str(row.get("bucket", "")).lower() == "standard")
        critical = sum(1 for row in subdomain_rows if str(row.get("bucket", "")).lower() == "critical")

        subdomain_chart = _build_pie_chart(
            ["Active", "Inactive"],
            [active_count, inactive_count],
            ["#16a34a", "#dc2626"],
        )
        if subdomain_chart:
            elements.append(subdomain_chart)
            elements.append(Spacer(1, 8))

        bucket_chart = _build_bar_chart(
            "Subdomain Classification",
            ["PQC Ready", "Standard", "Critical"],
            [pqc_ready, standard, critical],
            "#0050cb",
        )
        if bucket_chart:
            elements.append(bucket_chart)
            elements.append(Spacer(1, 8))

        subdomain_table = _build_subdomain_table(subdomain_rows)
        if subdomain_table:
            elements.append(subdomain_table)
            elements.append(Spacer(1, 12))

    # 3rd-party / vulnerability asset tables
    vuln_assets = data.get("vulnerable_assets", [])
    if vuln_assets:
        elements.append(Paragraph("Vulnerable Assets", heading_style))
        table_data = [["Asset Name", "Algorithm", "TLS Version", "Status"]]
        for asset in vuln_assets[:12]:
            scan = asset.get("scan_result", {})
            table_data.append([
                asset.get("name", ""),
                scan.get("algorithm", ""),
                scan.get("tls_version", ""),
                asset.get("risk", {}).get("risk_level", "Unknown"),
            ])
        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(data.get("theme_color", "#0050cb"))),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#fff7ed")),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 12))

    # Master inventory / assets
    assets = data.get("assets", [])
    if assets:
        elements.append(Paragraph("Master Asset Inventory", heading_style))
        elements.append(Paragraph(f"Total monitored assets: {len(assets)}", normal_style))
        elements.append(Spacer(1, 6))

        master_rows = [["Asset", "Type", "Risk", "Algorithm", "Subdomains"]]
        for asset in assets[:20]:
            scan = asset.get("scan_result", {})
            sub_count = len(asset.get("subdomains", []))
            master_rows.append([
                asset.get("name", ""),
                asset.get("type", "Unknown"),
                asset.get("risk", {}).get("risk_level", "Unknown"),
                scan.get("algorithm", "N/A"),
                str(sub_count),
            ])
        table = Table(master_rows, repeatRows=1)
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(data.get("secondary_theme_color", "#0f172a"))),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ]
        for row_index, asset in enumerate(assets[:20], start=1):
            table_style.append(("TEXTCOLOR", (2, row_index), (2, row_index), _risk_color(asset.get("risk", {}).get("risk_level", ""))))
        table.setStyle(TableStyle(table_style))
        elements.append(table)
        elements.append(Spacer(1, 12))

    mobile_rows = data.get("mobile_rows", [])
    if mobile_rows:
        elements.append(Paragraph("Mobile Application Discovery", heading_style))
        platform_counts = {}
        for row in mobile_rows:
            for app in row.get("apps", []):
                platform = app.get("platform", "unknown")
                platform_counts[platform] = platform_counts.get(platform, 0) + 1

        if platform_counts:
            labels = list(platform_counts.keys())
            values = list(platform_counts.values())
            drawing = _build_bar_chart("Mobile Platform Split", labels, values, "#16a34a")
            if drawing:
                elements.append(drawing)
                elements.append(Spacer(1, 6))

        mobile_table_rows = [["Domain", "Platform", "App", "Risk Score"]]
        for row in mobile_rows[:10]:
            for app in row.get("apps", []):
                mobile_table_rows.append([
                    row.get("domain", ""),
                    app.get("platform", ""),
                    app.get("name", ""),
                    str(app.get("risk_score", 0)),
                ])
        mobile_table = Table(mobile_table_rows, repeatRows=1)
        mobile_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#166534")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f0fdf4")),
        ]))
        elements.append(mobile_table)
        elements.append(Spacer(1, 12))

    recommendations = data.get("recommendations", [])
    elements.append(Paragraph("Actionable Recommendations", heading_style))
    if recommendations:
        for recommendation in recommendations[:8]:
            elements.append(Paragraph(f"• {recommendation}", normal_style))
    else:
        elements.append(Paragraph("No critical recommendations.", normal_style))

    doc.build(elements)

    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes