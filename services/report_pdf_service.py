import io
import math
import re

from services.report_export_service import safe_filename


PAGE_W = 595
PAGE_H = 842
MARGIN = 42


def reporting_pdf_response(context):
    pdf = _Pdf()
    _draw_report(pdf, context)
    filename = safe_filename(report_filename_prefix(context), context["start_time"], context["end_time"], "pdf")
    return filename, pdf.render()


def report_filename_prefix(context):
    selected = context.get("selected_devices") or []
    if selected:
        label = report_filename_label(selected[0], 200)
        suffix_at = label.find(" (")
        if suffix_at >= 0:
            label = label[:suffix_at].strip()
        return f"netspecter-{label or 'device'}-overview"
    if context.get("selected_application"):
        return f"netspecter-{report_filename_label(context.get('selected_application'), 120) or 'application'}-overview"
    if context.get("selected_domain"):
        return f"netspecter-{report_filename_label(context.get('selected_domain'), 200) or 'domain'}-overview"
    return "netspecter-management-overview"


def report_filename_label(value, max_length):
    return str(value or "")[:max_length].strip()


def _draw_report(pdf, context):
    if str(context.get("report_type") or "").strip().lower().startswith("internet"):
        _draw_internet_report(pdf, context)
        return

    overview = context["overview"]
    category_rows = list(context.get("category_rows") or [])
    category_report = context.get("category_report") or {}
    findings = context.get("findings") or {}
    ai_summary = context.get("ai_summary") or {}

    report_title = str(context.get("report_type") or "Management Overview").strip()
    if not report_title.lower().endswith("report"):
        report_title += " Report"
    _management_header(pdf, report_title, _report_scope(context), context["start_time"], context["end_time"])

    y = 724
    pdf.text(MARGIN, y, "EXECUTIVE SUMMARY", 9, bold=True, color=(0.28, 0.40, 0.58))
    y -= 58
    large_cards = [
        ("Total Traffic", _fmt_mb(overview.get("total_mb", 0)), "Across selected period", "#1473e6", "up/down"),
        ("Upload", _fmt_mb(overview.get("uploaded_mb", 0)), "Outbound traffic", "#15965f", "up"),
        ("Download", _fmt_mb(overview.get("downloaded_mb", 0)), "Inbound traffic", "#7c3fd6", "down"),
    ]
    _large_kpi_cards(pdf, large_cards, MARGIN, y, PAGE_W - (MARGIN * 2))
    y -= 74
    small_cards = [
        ("Active Devices", f"{overview.get('active_devices', 0):,}", f"{overview.get('devices', 0):,} monitored", "#1473e6", "device"),
        ("Applications", f"{overview.get('applications', 0):,}", "Detected categories", "#7c3fd6", "grid"),
        ("Destinations", f"{overview.get('unique_destinations', 0):,}", "Unique endpoints", "#13b8b6", "globe"),
        ("AI Services Traffic", _fmt_mb(ai_summary.get("attributed_mb") or 0), _ai_share_text(ai_summary, overview), "#f28a20", "ai"),
    ]
    _small_kpi_cards(pdf, small_cards, MARGIN, y, PAGE_W - (MARGIN * 2))

    y -= 94
    coverage = float(category_report.get("classification_coverage_pct") or 0)
    app_w = 382
    side_w = PAGE_W - (MARGIN * 2) - app_w - 10
    _application_usage_card(pdf, category_rows, coverage, MARGIN, y - 210, app_w, 210)
    _status_panel(pdf, findings, MARGIN + app_w + 10, y - 92, side_w, 92)
    _ai_panel(pdf, ai_summary, MARGIN + app_w + 10, y - 210, side_w, 108)

    y -= 226
    y = _category_table(pdf, category_rows, MARGIN, y)
    if y < 170:
        _draw_footer(pdf, len(pdf.pages))
        pdf.new_page()
        _management_header(pdf, "Management Overview Report", "Management Overview", "", "")
        y = 724
    device_rows = [
        [
            str(index),
            _row_value(row, "name", "") or _row_value(row, "ip", ""),
            _row_value(row, "mac", ""),
            _row_value(row, "ip", ""),
            _fmt_mb(_row_value(row, "total_mb", 0)),
            _fmt_mb(_row_value(row, "uploaded_mb", 0)),
            _fmt_mb(_row_value(row, "downloaded_mb", 0)),
        ]
        for index, row in enumerate((context.get("top_devices") or []), 1)
    ]
    _table_paginated(
        pdf,
        "TOP DEVICES",
        ["#", "Device", "MAC", "IP Address", "Total", "Upload", "Download"],
        device_rows,
        MARGIN,
        y - 10,
        [26, 142, 108, 78, 58, 50, 50],
        min_y=70,
    )
    _draw_footer(pdf, len(pdf.pages))


def _draw_internet_report(pdf, context):
    overview = context["overview"]
    rollup = context.get("internet_quality_rollup") or {}
    issue_rows = list(context.get("internet_issue_rows") or [])
    speed_rows = list(context.get("speedtest_rows") or [])
    samples = int(_row_value(rollup, "samples", 0) or 0)
    issues = int(_row_value(rollup, "issue_samples", 0) or 0)
    issue_rate = (issues / samples * 100) if samples else 0.0

    pdf.rect(0, 758, PAGE_W, 84, fill=(0.03, 0.08, 0.15), stroke=(0.03, 0.08, 0.15))
    pdf.rect(0, 754, PAGE_W, 4, fill=(0.00, 0.78, 0.92), stroke=(0.00, 0.78, 0.92))
    pdf.text(MARGIN, 808, "Internet Report", 20, bold=True, color=(1, 1, 1))
    pdf.text(MARGIN, 787, _report_scope(context), 9, color=(0.73, 0.82, 0.94))
    pdf.text(MARGIN, 771, f"{context['start_time']} to {context['end_time']}", 8, color=(0.73, 0.82, 0.94))
    pdf.text(455, 808, "Quality and outages", 9, bold=True, color=(0.73, 0.82, 0.94))

    stats = [
        ("Total Traffic", _fmt_mb(overview.get("total_mb", 0)), "Selected period"),
        ("Quality Samples", f"{samples:,}", "Monitor checks"),
        ("Issue Samples", f"{issues:,}", f"{issue_rate:.1f}% of checks"),
        ("Worst Latency", _fmt_metric(_row_value(rollup, "worst_latency_ms"), " ms"), "Internet"),
        ("Worst Loss", _fmt_metric(_row_value(rollup, "worst_loss_pct"), "%"), "Packet loss"),
        ("Worst DNS", _fmt_metric(_row_value(rollup, "worst_dns_ms"), " ms"), "DNS response"),
    ]
    _kpi_cards(pdf, stats, 704)

    y = 584
    issue_table_rows = [
        [
            _row_value(row, "ts", ""),
            _row_value(row, "status", "Issue"),
            _clip(_row_value(row, "diagnosis", "Internet quality issue recorded."), 34),
            _fmt_metric(_row_value(row, "internet_latency_ms"), " ms"),
            _fmt_metric(_row_value(row, "internet_loss_pct"), "%"),
            _fmt_metric(_row_value(row, "jitter_ms"), " ms"),
            _fmt_metric(_row_value(row, "dns_ms"), " ms"),
        ]
        for row in issue_rows[:18]
    ]
    y = _table(
        pdf,
        "Internet Quality Issues",
        ["When", "Status", "What happened", "Latency", "Loss", "Jitter", "DNS"],
        issue_table_rows,
        MARGIN,
        y,
        [92, 56, 150, 52, 42, 45, 45],
    )
    if len(issue_rows) > 18:
        pdf.text(MARGIN + 6, y + 10, f"{len(issue_rows) - 18} more issue sample(s) are available in the Excel export.", 8, color=(0.36, 0.43, 0.54))
        y -= 16

    speed_table_rows = [
        [
            _row_value(row, "ts", ""),
            _row_value(row, "source", ""),
            _fmt_metric(_row_value(row, "latency_ms"), " ms"),
            _fmt_metric(_row_value(row, "download_mbps"), " Mbps"),
            _fmt_metric(_row_value(row, "upload_mbps"), " Mbps"),
            "OK" if int(_row_value(row, "success", 0) or 0) else "Failed",
        ]
        for row in speed_rows[:8]
    ]
    _table(
        pdf,
        "Speed Tests",
        ["When", "Source", "Latency", "Download", "Upload", "Status"],
        speed_table_rows,
        MARGIN,
        y - 6,
        [102, 84, 68, 88, 88, 50],
    )

    pdf.line(MARGIN, 42, PAGE_W - MARGIN, 42, color=(0.86, 0.91, 0.97))
    pdf.text(MARGIN, 28, "Internet quality issues are recorded monitor samples where status was not healthy. Speed tests are shown separately because they measure bandwidth on demand or schedule.", 7, color=(0.36, 0.43, 0.54))


def _report_scope(context):
    selected = context.get("selected_devices") or []
    if selected:
        return f"Device investigation: {selected[0]}"
    if context.get("selected_application"):
        return f"Application focus: {context.get('selected_application')}"
    if context.get("selected_domain"):
        return f"Destination focus: {context.get('selected_domain')}"
    return str(context.get("report_type") or "Management Overview")


def _management_header(pdf, title, scope, start_time, end_time):
    navy = (0.02, 0.07, 0.14)
    pdf.rect(0, 758, PAGE_W, 84, fill=navy, stroke=navy)
    pdf.rect(0, 754, PAGE_W, 4, fill=(0.08, 0.39, 0.84), stroke=(0.08, 0.39, 0.84))
    for offset in range(0, 150, 18):
        pdf.line(390 + offset, 758, PAGE_W + offset, 842, color=(0.04, 0.20, 0.38), width=0.35)
    _shield_mark(pdf, MARGIN + 16, 800)
    pdf.text(MARGIN + 48, 808, title, 20, bold=True, color=(1, 1, 1))
    pdf.text(MARGIN + 48, 786, scope, 9, color=(0.76, 0.84, 0.94))
    date_line = f"{start_time} to {end_time}".strip()
    if date_line != "to":
        pdf.text(MARGIN + 48, 771, date_line, 8, color=(0.76, 0.84, 0.94))
    pdf.round_rect(PAGE_W - MARGIN - 96, 804, 86, 22, fill=(0.17, 0.25, 0.58), stroke=(0.20, 0.31, 0.70))
    pdf.text(PAGE_W - MARGIN - 84, 811, "Executive Report", 8, bold=True, color=(1, 1, 1))


def _shield_mark(pdf, cx, cy):
    pdf.line(cx - 12, cy + 13, cx, cy + 18, color=(0.13, 0.47, 0.92), width=5)
    pdf.line(cx, cy + 18, cx + 12, cy + 13, color=(1, 1, 1), width=5)
    pdf.line(cx - 12, cy + 13, cx - 12, cy - 6, color=(0.13, 0.47, 0.92), width=5)
    pdf.line(cx + 12, cy + 13, cx + 12, cy - 6, color=(1, 1, 1), width=5)
    pdf.line(cx - 12, cy - 6, cx, cy - 18, color=(0.13, 0.47, 0.92), width=5)
    pdf.line(cx + 12, cy - 6, cx, cy - 18, color=(0.13, 0.47, 0.92), width=5)


def _large_kpi_cards(pdf, cards, x, y, width):
    gap = 10
    card_w = (width - gap * 2) / 3
    for index, (label, value, detail, color_hex, icon) in enumerate(cards):
        card_x = x + index * (card_w + gap)
        _card(pdf, card_x, y, card_w, 58)
        accent = _hex_to_rgb(color_hex)
        pdf.circle(card_x + 30, y + 29, 18, fill=accent, stroke=accent)
        _icon(pdf, icon, card_x + 30, y + 29, color=(1, 1, 1), size=15)
        pdf.text(card_x + 64, y + 40, label, 7, bold=True, color=(0.04, 0.14, 0.30))
        pdf.text(card_x + 64, y + 20, value, 16, bold=True, color=(0.04, 0.10, 0.22))
        pdf.text(card_x + 64, y + 8, detail, 7, color=(0.24, 0.34, 0.50))


def _small_kpi_cards(pdf, cards, x, y, width):
    gap = 0
    card_w = width / 4
    _card(pdf, x, y, width, 58)
    for index, (label, value, detail, color_hex, icon) in enumerate(cards):
        card_x = x + index * card_w
        if index:
            pdf.line(card_x, y, card_x, y + 58, color=(0.87, 0.91, 0.96), width=0.5)
        accent = _hex_to_rgb(color_hex)
        pale = tuple(1 - ((1 - c) * 0.16) for c in accent)
        pdf.circle(card_x + 28, y + 29, 18, fill=pale, stroke=pale)
        _icon(pdf, icon, card_x + 28, y + 29, color=accent, size=12)
        pdf.text(card_x + 56, y + 40, label, 7, bold=True, color=(0.04, 0.14, 0.30))
        pdf.text(card_x + 56, y + 20, value, 15, bold=True, color=(0.04, 0.10, 0.22))
        pdf.text(card_x + 56, y + 8, _clip(detail, 20), 7, color=(0.24, 0.34, 0.50))


def _icon(pdf, name, cx, cy, color=(1, 1, 1), size=12):
    if name == "up/down":
        pdf.text(cx - 9, cy - 5, "up/down", 5, bold=True, color=color)
    elif name == "up":
        pdf.text(cx - 4, cy - 6, "^", size + 5, bold=True, color=color)
    elif name == "down":
        pdf.text(cx - 4, cy - 6, "v", size + 5, bold=True, color=color)
    elif name == "device":
        pdf.rect(cx - 7, cy - 9, 14, 18, fill=(1, 1, 1), stroke=color)
        pdf.line(cx - 5, cy - 5, cx + 5, cy - 5, color=color, width=1)
    elif name == "grid":
        for dx in (-6, 3):
            for dy in (-6, 3):
                pdf.rect(cx + dx, cy + dy, 5, 5, fill=(1, 1, 1), stroke=color)
    elif name == "globe":
        pdf.circle(cx, cy, 10, fill=(1, 1, 1), stroke=color)
        pdf.line(cx - 10, cy, cx + 10, cy, color=color, width=1)
        pdf.line(cx, cy - 10, cx, cy + 10, color=color, width=1)
    elif name == "ai":
        pdf.text(cx - 7, cy - 5, "AI", size, bold=True, color=color)


def _card(pdf, x, y, w, h):
    pdf.round_rect(x, y, w, h, fill=(1, 1, 1), stroke=(0.84, 0.89, 0.96))


def _ai_share_text(ai_summary, overview):
    total = float(overview.get("total_mb") or 0)
    ai_mb = float(ai_summary.get("attributed_mb") or 0)
    if total <= 0:
        return "Attributed AI traffic"
    return f"{(ai_mb / total * 100):.1f}% of total traffic"


def _kpi_cards(pdf, stats, y):
    for index, (label, value, detail) in enumerate(stats):
        x = MARGIN + (index % 3) * 171
        card_y = y - (index // 3) * 58
        pdf.round_rect(x, card_y, 156, 44, fill=(0.96, 0.98, 1.0), stroke=(0.80, 0.87, 0.95))
        pdf.text(x + 10, card_y + 29, label, 7, bold=True, color=(0.36, 0.43, 0.54))
        pdf.text(x + 10, card_y + 13, value, 13, bold=True, color=(0.05, 0.12, 0.22))
        pdf.text(x + 88, card_y + 14, _clip(detail, 18), 6, color=(0.48, 0.56, 0.68))


def _status_panel(pdf, findings, x, y, w, h):
    findings = findings or {}
    rating = str(findings.get("rating", "Low") if hasattr(findings, "get") else "Low" or "Low")
    tone = (0.13, 0.64, 0.42)
    if rating.lower() in {"medium", "watch", "moderate"}:
        tone = (0.86, 0.53, 0.16)
    elif rating.lower() in {"high", "critical"}:
        tone = (0.86, 0.28, 0.28)
    _card(pdf, x, y, w, h)
    pdf.text(x + 12, y + h - 20, "USAGE STATUS", 8, bold=True, color=(0.04, 0.14, 0.30))
    pdf.circle(x + 28, y + h - 50, 15, fill=tone, stroke=tone)
    pdf.text(x + 23, y + h - 56, "ok", 8, bold=True, color=(1, 1, 1))
    score = findings.get("score", 0) if hasattr(findings, "get") else 0
    pdf.text(x + 52, y + h - 47, f"{rating} ({score} points)", 13, bold=True, color=tone)
    reasons = findings.get("reasons") if hasattr(findings, "get") else []
    reasons = reasons or []
    if not reasons:
        pdf.text(x + 52, y + h - 64, "No notable usage concerns detected.", 7, color=(0.36, 0.43, 0.54))
    for offset, reason in enumerate(reasons[:3]):
        pdf.text(x + 12, y + h - 66 - (offset * 12), _clip(reason, 38), 7, color=(0.36, 0.43, 0.54))


def _ai_panel(pdf, ai_summary, x, y, w, h):
    _card(pdf, x, y, w, h)
    pdf.text(x + 12, y + h - 20, "AI SERVICES OVERVIEW", 8, bold=True, color=(0.04, 0.14, 0.30))
    if not ai_summary.get("services_detected"):
        pdf.text(x + 12, y + h - 44, "No AI services detected", 11, bold=True, color=(0.04, 0.10, 0.22))
        pdf.text(x + 12, y + h - 60, "No matching evidence in this period.", 7, color=(0.36, 0.43, 0.54))
        return
    services = ai_summary.get("services") or []
    top = next((row for row in services if float(row.get("attributed_mb") or 0) > 0), services[0] if services else {})
    purple = (0.43, 0.32, 0.86)
    pdf.circle(x + 28, y + h - 48, 15, fill=(0.94, 0.91, 1.0), stroke=(0.94, 0.91, 1.0))
    pdf.text(x + 21, y + h - 54, "AI", 9, bold=True, color=purple)
    pdf.text(x + 52, y + h - 42, _fmt_mb(ai_summary.get("attributed_mb") or 0), 12, bold=True, color=purple)
    pdf.text(x + 52, y + h - 57, "attributed AI traffic", 7, color=(0.36, 0.43, 0.54))
    pdf.text(x + 18, y + h - 78, f"{ai_summary.get('services_detected', 0)} services detected", 8, bold=True, color=purple)
    pdf.text(x + 18, y + h - 94, f"{len(ai_summary.get('devices') or [])} devices", 8, bold=True, color=purple)
    pdf.text(x + 94, y + h - 78, "Top service", 7, color=(0.36, 0.43, 0.54))
    pdf.text(x + 94, y + h - 91, _clip(top.get("service", "Unknown"), 22), 8, bold=True, color=(0.04, 0.14, 0.30))
    pdf.text(x + 94, y + h - 105, f"Coverage: {_clip(ai_summary.get('attribution_coverage', 'Unknown'), 14)}", 7, color=(0.36, 0.43, 0.54))


def _application_usage_card(pdf, category_rows, coverage, x, y, w, h):
    _card(pdf, x, y, w, h)
    pdf.text(x + 12, y + h - 20, "APPLICATION USAGE", 9, bold=True, color=(0.04, 0.14, 0.30))
    pdf.text(x + 12, y + h - 36, f"{coverage:.1f}% of total traffic is attributed to applications.", 7, color=(0.24, 0.34, 0.50))
    rows = [row for row in category_rows if _row_value(row, "category") != "Traffic Without Application Attribution"][:6]
    if not rows:
        pdf.text(x + 12, y + h - 60, "No classified application traffic found for this period.", 8, color=(0.36, 0.43, 0.54))
        return
    _draw_pie(pdf, x + 68, y + 86, 56, rows, center_label="")
    table_x = x + 150
    table_y = y + h - 76
    pdf.text(table_x, table_y, "Category", 7, bold=True, color=(0.24, 0.34, 0.50))
    pdf.text(table_x + 126, table_y, "% Total", 7, bold=True, color=(0.24, 0.34, 0.50))
    pdf.text(table_x + 190, table_y, "Traffic", 7, bold=True, color=(0.24, 0.34, 0.50))
    row_y = table_y - 18
    for row in rows:
        category = str(_row_value(row, "category", ""))
        pct = float(_row_value(row, "share_total_pct", 0) or 0)
        traffic = _fmt_mb(_row_value(row, "total_mb", 0))
        color = _category_color(row)
        pdf.circle(table_x + 4, row_y + 3, 3, fill=color, stroke=color)
        pdf.text(table_x + 14, row_y, _clip(category, 22), 7, color=(0.04, 0.14, 0.30))
        pdf.text(table_x + 130, row_y, f"{pct:.1f}%", 7, color=(0.04, 0.14, 0.30))
        pdf.text(table_x + 190, row_y, traffic, 7, color=(0.04, 0.14, 0.30))
        row_y -= 17


def _category_table(pdf, category_rows, x, y):
    rows = [row for row in category_rows if _row_value(row, "category") != "Traffic Without Application Attribution"][:8]
    table_rows = []
    for row in rows:
        apps = _row_value(row, "application_names", []) or []
        table_rows.append([
            ("dot", _category_color(row)),
            _row_value(row, "category", ""),
            _fmt_mb(_row_value(row, "total_mb", 0)),
            f"{float(_row_value(row, 'share_total_pct', 0) or 0):.1f}%",
            ", ".join(str(app) for app in apps[:5]),
        ])
    return _table_paginated(
        pdf,
        "CATEGORY DETAIL",
        ["", "Category", "Traffic", "% Total", "Top Applications"],
        table_rows,
        x,
        y,
        [20, 138, 72, 58, 224],
        min_y=170,
    )


def _table(pdf, title, headers, rows, x, y, widths):
    pdf.text(x, y, title, 11, bold=True, color=(0.05, 0.12, 0.22))
    y -= 18
    pdf.rect(x, y - 3, sum(widths), 18, fill=(0.91, 0.95, 0.99), stroke=(0.78, 0.86, 0.96))
    col_x = x
    for header, width in zip(headers, widths):
        pdf.text(col_x + 6, y + 3, str(header), 7, bold=True, color=(0.25, 0.34, 0.47))
        col_x += width
    y -= 18
    if not rows:
        pdf.text(x + 6, y + 3, "No data found for this period.", 8, color=(0.36, 0.43, 0.54))
        return y - 18
    for row in rows:
        pdf.line(x, y + 12, x + sum(widths), y + 12, color=(0.86, 0.91, 0.97))
        col_x = x
        for value, width in zip(row, widths):
            pdf.text(col_x + 6, y + 1, _clip(str(value), max(8, int(width / 5.3))), 8, color=(0.05, 0.12, 0.22))
            col_x += width
        y -= 17
    return y - 10


def _table_paginated(pdf, title, headers, rows, x, y, widths, min_y=64):
    table_w = sum(widths)
    pdf.text(x, y, title, 9, bold=True, color=(0.04, 0.14, 0.30))
    y -= 18

    def header_at(current_y):
        pdf.rect(x, current_y - 3, table_w, 18, fill=(0.95, 0.97, 0.99), stroke=(0.84, 0.89, 0.96))
        col_x = x
        for header, width in zip(headers, widths):
            pdf.text(col_x + 5, current_y + 3, str(header), 7, bold=True, color=(0.24, 0.34, 0.50))
            col_x += width
        return current_y - 18

    y = header_at(y)
    if not rows:
        pdf.text(x + 6, y + 3, "No data found for this period.", 8, color=(0.36, 0.43, 0.54))
        return y - 20

    for index, row in enumerate(rows):
        row_height = _row_height(row, widths)
        if y - row_height < min_y:
            _draw_footer(pdf, len(pdf.pages))
            pdf.new_page()
            _management_header(pdf, "Management Overview Report", "Management Overview", "", "")
            y = 724
            pdf.text(x, y, f"{title} CONTINUED", 9, bold=True, color=(0.04, 0.14, 0.30))
            y -= 18
            y = header_at(y)
        fill = (0.985, 0.992, 1.0) if index % 2 else (1, 1, 1)
        pdf.rect(x, y - row_height + 13, table_w, row_height, fill=fill, stroke=(0.90, 0.93, 0.97))
        col_x = x
        max_lines = max(1, int((row_height - 8) / 9))
        for value, width in zip(row, widths):
            if isinstance(value, tuple) and value and value[0] == "dot":
                pdf.circle(col_x + 10, y + 4, 4, fill=value[1], stroke=value[1])
            else:
                lines = _wrap_text(str(value), max(5, int((width - 10) / 4.2)))[:max_lines]
                for line_no, line in enumerate(lines):
                    size = 7 if len(lines) > 1 else 8
                    pdf.text(col_x + 5, y + 3 - (line_no * 9), line, size, color=(0.04, 0.14, 0.30))
            col_x += width
        y -= row_height
    return y - 12


def _row_height(row, widths):
    max_lines = 1
    for value, width in zip(row, widths):
        if isinstance(value, tuple):
            continue
        max_lines = max(max_lines, len(_wrap_text(str(value), max(5, int((width - 10) / 4.2)))))
    return max(18, 10 + min(max_lines, 3) * 9)


def _draw_pie(pdf, cx, cy, radius, rows, center_label=""):
    start = -90.0
    total = 0.0
    for row in rows:
        if _row_value(row, "category") == "Traffic Without Application Attribution":
            continue
        pct = max(0.0, float(_row_value(row, "share_classified_pct", _row_value(row, "share_total_pct", 0)) or 0))
        if pct <= 0:
            continue
        end = min(270.0, start + pct * 3.6)
        pdf.wedge(cx, cy, radius, start, end, fill=_category_color(row))
        start = end
        total += pct
        if total >= 100:
            break
    pdf.circle(cx, cy, 31, fill=(1, 1, 1), stroke=(1, 1, 1))
    if center_label:
        pdf.text(cx - 22, cy - 3, center_label, 8, bold=True, color=(0.05, 0.12, 0.22))


def _fmt_mb(value):
    value = float(value or 0)
    if value >= 1024:
        return f"{value / 1024:.2f} GB"
    return f"{value:.2f} MB"


def _fmt_metric(value, suffix="", decimals=1):
    if value is None or value == "":
        return "-"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "-"
    return f"{number:.{decimals}f}{suffix}"


def _clip(text, limit):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text if len(text) <= limit else text[: max(0, limit - 1)].rstrip() + "..."


def _wrap_text(text, limit):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if not text:
        return [""]
    limit = max(4, int(limit or 20))
    lines = []
    current = ""
    for word in text.split(" "):
        if len(word) > limit:
            if current:
                lines.append(current)
                current = ""
            lines.extend(word[i:i + limit] for i in range(0, len(word), limit))
            continue
        candidate = f"{current} {word}".strip()
        if len(candidate) <= limit:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _row_value(row, key, default=""):
    if row is None:
        return default
    if hasattr(row, "get"):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default


def _hex_to_rgb(value):
    text = str(value or "").strip().lstrip("#")
    if len(text) == 3:
        text = "".join(ch * 2 for ch in text)
    try:
        return tuple(int(text[i : i + 2], 16) / 255 for i in (0, 2, 4))
    except Exception:
        return (0.39, 0.45, 0.55)


def _category_color(row):
    category = str(_row_value(row, "category", "") or "").lower()
    palette = [
        ("unknown", "#64748b"),
        ("video", "#ef4444"),
        ("youtube", "#ef4444"),
        ("software", "#16a34a"),
        ("update", "#16a34a"),
        ("social", "#f97316"),
        ("facebook", "#f97316"),
        ("instagram", "#f97316"),
        ("tiktok", "#f97316"),
        ("ai", "#7c3fd6"),
        ("cloud", "#0ea5e9"),
        ("microsoft", "#2563eb"),
    ]
    for needle, color in palette:
        if needle in category:
            return _hex_to_rgb(color)
    return _hex_to_rgb(_row_value(row, "color", "#94a3b8"))


def _draw_footer(pdf, page_number):
    pdf.line(MARGIN, 42, PAGE_W - MARGIN, 42, color=(0.86, 0.91, 0.97))
    pdf.circle(MARGIN + 7, 24, 6, fill=(1, 1, 1), stroke=(0.55, 0.64, 0.76))
    pdf.text(MARGIN + 5, 21, "i", 7, bold=True, color=(0.55, 0.64, 0.76))
    pdf.text(MARGIN + 22, 29, "Limitations:", 7, bold=True, color=(0.10, 0.19, 0.33))
    footer = "identity depends on maintained labels and device assignments; encrypted, CDN, and shared-cloud traffic may not always identify the exact application or person."
    pdf.text(MARGIN + 72, 29, _clip(footer, 88), 6.5, color=(0.36, 0.43, 0.54))
    pdf.text(PAGE_W - MARGIN - 118, 24, "Report generated by", 7, color=(0.36, 0.43, 0.54))
    pdf.text(PAGE_W - MARGIN - 30, 24, "NetSpecter", 7, bold=True, color=(0.04, 0.32, 0.70))
    pdf.text(PAGE_W / 2 - 12, 24, f"Page {page_number}", 7, color=(0.48, 0.56, 0.68))


def _pdf_escape(text):
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class _Pdf:
    def __init__(self):
        self.pages = [[]]

    @property
    def ops(self):
        return self.pages[-1]

    def new_page(self):
        self.pages.append([])

    def text(self, x, y, text, size=10, bold=False, color=(0, 0, 0)):
        font = "F2" if bold else "F1"
        self.ops.append(
            f"BT /{font} {size} Tf {_rgb(color)} rg 1 0 0 1 {x:.2f} {y:.2f} Tm ({_pdf_escape(text)}) Tj ET"
        )

    def line(self, x1, y1, x2, y2, color=(0, 0, 0), width=0.5):
        self.ops.append(f"q {width:.2f} w {_rgb(color)} RG {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S Q")

    def rect(self, x, y, w, h, fill=(1, 1, 1), stroke=(0, 0, 0)):
        self.ops.append(f"q {_rgb(fill)} rg {_rgb(stroke)} RG {x:.2f} {y:.2f} {w:.2f} {h:.2f} re B Q")

    def round_rect(self, x, y, w, h, fill=(1, 1, 1), stroke=(0, 0, 0)):
        self.rect(x, y, w, h, fill, stroke)

    def circle(self, cx, cy, r, fill=(1, 1, 1), stroke=(0, 0, 0)):
        c = 0.5522847498 * r
        self.ops.append(
            f"q {_rgb(fill)} rg {_rgb(stroke)} RG "
            f"{cx+r:.2f} {cy:.2f} m "
            f"{cx+r:.2f} {cy+c:.2f} {cx+c:.2f} {cy+r:.2f} {cx:.2f} {cy+r:.2f} c "
            f"{cx-c:.2f} {cy+r:.2f} {cx-r:.2f} {cy+c:.2f} {cx-r:.2f} {cy:.2f} c "
            f"{cx-r:.2f} {cy-c:.2f} {cx-c:.2f} {cy-r:.2f} {cx:.2f} {cy-r:.2f} c "
            f"{cx+c:.2f} {cy-r:.2f} {cx+r:.2f} {cy-c:.2f} {cx+r:.2f} {cy:.2f} c B Q"
        )

    def wedge(self, cx, cy, r, start_deg, end_deg, fill=(0.5, 0.5, 0.5)):
        points = [(cx, cy)]
        steps = max(2, int(abs(end_deg - start_deg) / 8) + 1)
        for i in range(steps + 1):
            angle = math.radians(start_deg + (end_deg - start_deg) * i / steps)
            points.append((cx + math.cos(angle) * r, cy + math.sin(angle) * r))
        path = [f"{points[0][0]:.2f} {points[0][1]:.2f} m"]
        path.extend(f"{x:.2f} {y:.2f} l" for x, y in points[1:])
        path.append("h f")
        self.ops.append(f"q {_rgb(fill)} rg {' '.join(path)} Q")

    def render(self):
        page_count = len(self.pages)
        font_regular_id = 3 + page_count * 2
        font_bold_id = font_regular_id + 1
        kids = " ".join(f"{3 + index * 2} 0 R" for index in range(page_count))
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            f"<< /Type /Pages /Kids [{kids}] /Count {page_count} >>".encode("ascii"),
        ]
        for index, page_ops in enumerate(self.pages):
            page_id = 3 + index * 2
            content_id = page_id + 1
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 {font_regular_id} 0 R /F2 {font_bold_id} 0 R >> >> "
                f"/Contents {content_id} 0 R >>"
                .encode("ascii")
            )
            stream = "\n".join(page_ops).encode("latin-1", "replace")
            objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")
        objects.extend([
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        ])
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n")
        offsets = [0]
        for i, obj in enumerate(objects, 1):
            offsets.append(out.tell())
            out.write(f"{i} 0 obj\n".encode("ascii"))
            out.write(obj)
            out.write(b"\nendobj\n")
        xref = out.tell()
        out.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        out.write(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            out.write(f"{offset:010d} 00000 n \n".encode("ascii"))
        out.write(
            f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
        )
        return out.getvalue()


def _rgb(color):
    return " ".join(f"{float(component):.3f}" for component in color[:3])
