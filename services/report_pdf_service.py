import io
import math
import re

from netspecter_config import cfg
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
    if str(context.get("report_type") or "").strip().lower().startswith("internet"):
        return "netspecter-internet-quality"
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
    quality_rows = sorted(list(context.get("quality_rows") or []), key=lambda row: str(_row_value(row, "ts", "")))
    speed_rows = sorted(speed_rows, key=lambda row: str(_row_value(row, "ts", "")))
    expected = _expected_speed_config()
    health = _internet_health_score(rollup, issue_rows)
    speed_stats = _speed_stats(speed_rows, expected)

    _quality_header(pdf, context["start_time"], context["end_time"])
    y = 742
    pdf.text(MARGIN, y, "EXECUTIVE SUMMARY", 10, bold=True, color=(0.02, 0.35, 0.72))
    y -= 78
    availability = (max(0, samples - issues) / samples * 100) if samples else 100.0
    large_cards = [
        ("Internet Health", health["label"], f"{health['score']} / 100", health["detail"], health["color"], "ok"),
        ("Availability", f"{availability:.2f}%", "Uptime", "Total monitored time", "#1473e6", "globe"),
        ("Outages", f"{issues:,}", "Recorded", "Classified unhealthy samples", "#ef4444", "warn"),
        ("Total Downtime", _downtime_text(issues, samples, context), "This period", "Estimated from checks", "#1473e6", "clock"),
    ]
    _quality_large_cards(pdf, large_cards, MARGIN, y, PAGE_W - (MARGIN * 2))
    y -= 74
    secondary = [
        ("Total Traffic", _fmt_mb(overview.get("total_mb", 0)), "Selected period", "#1473e6", "cloud"),
        ("Quality Samples", f"{samples:,}", "Monitor checks", "#2563eb", "pulse"),
        ("Avg. Latency", _fmt_metric(_row_value(rollup, "avg_latency_ms"), " ms"), "Internet", "#14b8a6", "gauge"),
        ("Worst Latency", _fmt_metric(_row_value(rollup, "worst_latency_ms"), " ms"), "Recorded peak", "#64748b", "gauge"),
        ("Avg. Loss", _fmt_metric(_row_value(rollup, "avg_loss_pct"), "%"), "Packet loss", "#10b981", "shield"),
        ("Worst Loss", _fmt_metric(_row_value(rollup, "worst_loss_pct"), "%"), "Recorded peak", "#f59e0b", "bars"),
        ("Avg. DNS", _fmt_metric(_row_value(rollup, "avg_dns_ms"), " ms"), "DNS response", "#7c3fd6", "globe"),
    ]
    _quality_secondary_cards(pdf, secondary, MARGIN, y, PAGE_W - (MARGIN * 2))

    y -= 244
    chart_w = 372
    speed_w = PAGE_W - (MARGIN * 2) - chart_w - 12
    _quality_chart_card(pdf, quality_rows, issue_rows, MARGIN, y, chart_w, 232)
    _speed_performance_card(pdf, speed_rows, speed_stats, expected, MARGIN + chart_w + 12, y, speed_w, 232)

    y -= 120
    _quality_metric_cards(pdf, rollup, MARGIN, y, PAGE_W - (MARGIN * 2))

    y -= 118
    issue_w = 366
    _quality_issues_card(pdf, issue_rows, rollup, MARGIN, y, issue_w, 104)
    _quality_insights_card(pdf, _quality_insights(rollup, issue_rows, speed_stats, expected), MARGIN + issue_w + 12, y, PAGE_W - (MARGIN * 2) - issue_w - 12, 104)

    y -= 86
    _management_assessment_card(pdf, _internet_assessment(health, rollup, issue_rows, speed_stats, expected), MARGIN, y, PAGE_W - (MARGIN * 2), 58)
    _draw_internet_footer(pdf, len(pdf.pages))

    if speed_rows:
        pdf.new_page()
        _quality_header(pdf, context["start_time"], context["end_time"], title="Speed Test History")
        _draw_speed_history(pdf, speed_rows, expected)
    if issue_rows:
        pdf.new_page()
        _quality_header(pdf, context["start_time"], context["end_time"], title="Internet Quality Event Detail")
        _draw_issue_history(pdf, issue_rows)


def _report_scope(context):
    selected = context.get("selected_devices") or []
    if selected:
        return f"Device investigation: {selected[0]}"
    if context.get("selected_application"):
        return f"Application focus: {context.get('selected_application')}"
    if context.get("selected_domain"):
        return f"Destination focus: {context.get('selected_domain')}"
    return str(context.get("report_type") or "Management Overview")


def _quality_header(pdf, start_time, end_time, title="Internet Quality Report"):
    _management_header(pdf, title, "Internet Report", start_time, end_time)
    pdf.rect(0, 754, PAGE_W, 4, fill=(0.00, 0.78, 0.92), stroke=(0.00, 0.78, 0.92))
    pdf.round_rect(PAGE_W - MARGIN - 112, 804, 102, 22, fill=(0.10, 0.28, 0.70), stroke=(0.12, 0.36, 0.82))
    pdf.text(PAGE_W - MARGIN - 100, 811, "Quality & Availability", 8, bold=True, color=(1, 1, 1))


def _internet_health_score(rollup, issue_rows):
    samples = int(_row_value(rollup, "samples", 0) or 0)
    issues = int(_row_value(rollup, "issue_samples", 0) or 0)
    avg_latency = _num(_row_value(rollup, "avg_latency_ms"))
    worst_loss = _num(_row_value(rollup, "worst_loss_pct"))
    avg_loss = _num(_row_value(rollup, "avg_loss_pct"))
    avg_dns = _num(_row_value(rollup, "avg_dns_ms"))
    score = 100
    if samples:
        score -= min(45, int((issues / samples) * 100))
    if avg_latency > 80:
        score -= 10
    if avg_latency > 150:
        score -= 15
    if avg_loss > 1:
        score -= 10
    if worst_loss >= 10:
        score -= 8
    if avg_dns > 100:
        score -= 8
    score = max(0, min(100, score))
    if score >= 90:
        return {"score": score, "label": "Excellent", "detail": "Connection stable", "color": "#10b981"}
    if score >= 75:
        return {"score": score, "label": "Good", "detail": "Minor variation observed", "color": "#22c55e"}
    if score >= 55:
        return {"score": score, "label": "Fair", "detail": "Some degradation observed", "color": "#f59e0b"}
    if score >= 35:
        return {"score": score, "label": "Poor", "detail": "Quality concerns detected", "color": "#ef4444"}
    return {"score": score, "label": "Critical", "detail": "Connectivity degraded", "color": "#dc2626"}


def _quality_large_cards(pdf, cards, x, y, width):
    gap = 9
    first_w = width * 0.35
    rest_w = (width - first_w - gap * 3) / 3
    positions = [x, x + first_w + gap, x + first_w + gap + rest_w + gap, x + first_w + gap + rest_w * 2 + gap * 2]
    widths = [first_w, rest_w, rest_w, rest_w]
    for index, (label, value, subvalue, detail, color_hex, icon) in enumerate(cards):
        card_x, card_w = positions[index], widths[index]
        accent = _hex_to_rgb(color_hex)
        _card(pdf, card_x, y, card_w, 68)
        pdf.circle(card_x + 31, y + 34, 23 if index == 0 else 16, fill=tuple(1 - ((1 - c) * 0.18) for c in accent), stroke=(0.90, 0.95, 1.0))
        _quality_icon(pdf, icon, card_x + 31, y + 34, accent, 14)
        text_x = card_x + (70 if index == 0 else 54)
        pdf.text(text_x, y + 48, label, 7, bold=True, color=(0.04, 0.14, 0.30))
        pdf.text(text_x, y + 30, value, 14 if index else 16, bold=True, color=(0.04, 0.10, 0.22))
        pdf.text(text_x, y + 16, subvalue, 10 if index == 0 else 8, bold=index == 0, color=accent if index == 0 else (0.24, 0.34, 0.50))
        pdf.text(text_x, y + 5, _clip(detail, 28), 7, color=(0.24, 0.34, 0.50))


def _quality_secondary_cards(pdf, cards, x, y, width):
    gap = 5
    card_w = (width - gap * (len(cards) - 1)) / len(cards)
    for index, (label, value, detail, color_hex, icon) in enumerate(cards):
        card_x = x + index * (card_w + gap)
        accent = _hex_to_rgb(color_hex)
        _card(pdf, card_x, y, card_w, 58)
        pdf.circle(card_x + 18, y + 31, 12, fill=tuple(1 - ((1 - c) * 0.16) for c in accent), stroke=(0.90, 0.95, 1.0))
        _quality_icon(pdf, icon, card_x + 18, y + 31, accent, 9)
        pdf.text(card_x + 36, y + 41, label, 5.5, bold=True, color=(0.04, 0.14, 0.30))
        pdf.text(card_x + 36, y + 22, _clip(value, 13), 11, bold=True, color=(0.04, 0.10, 0.22))
        pdf.text(card_x + 36, y + 9, _clip(detail, 14), 6, color=(0.24, 0.34, 0.50))


def _quality_icon(pdf, name, cx, cy, color, size):
    if name == "ok":
        pdf.line(cx - 8, cy, cx - 2, cy - 7, color=color, width=4)
        pdf.line(cx - 2, cy - 7, cx + 10, cy + 8, color=color, width=4)
    elif name == "warn":
        pdf.text(cx - 5, cy - 7, "!", size + 5, bold=True, color=color)
    elif name == "clock":
        pdf.circle(cx, cy, 8, fill=(1, 1, 1), stroke=color)
        pdf.line(cx, cy, cx, cy + 5, color=color, width=1.3)
        pdf.line(cx, cy, cx + 4, cy - 2, color=color, width=1.3)
    else:
        _icon(pdf, name, cx, cy, color=color, size=size)


def _quality_chart_card(pdf, quality_rows, issue_rows, x, y, w, h):
    _card(pdf, x, y, w, h)
    pdf.text(x + 12, y + h - 18, "Internet Quality Over Time", 10, bold=True, color=(0.04, 0.14, 0.30))
    pdf.text(x + 12, y + h - 32, "Latency, packet loss and DNS response", 7, color=(0.24, 0.34, 0.50))
    chart_x, chart_y, chart_w, chart_h = x + 38, y + 68, w - 72, 112
    rows = _downsample_rows(quality_rows, 60)
    latency = [_num(_row_value(row, "internet_latency_ms")) for row in rows]
    jitter = [_num(_row_value(row, "jitter_ms")) for row in rows]
    loss = [_num(_row_value(row, "internet_loss_pct")) for row in rows]
    dns = [_num(_row_value(row, "dns_ms")) for row in rows]
    left_max = max([40.0] + latency + jitter + dns)
    right_max = max([5.0] + loss)
    _chart_grid(pdf, chart_x, chart_y, chart_w, chart_h, left_max, right_max)
    _line_series(pdf, latency, chart_x, chart_y, chart_w, chart_h, left_max, (0.09, 0.48, 0.96))
    _line_series(pdf, jitter, chart_x, chart_y, chart_w, chart_h, left_max, (0.50, 0.25, 0.85))
    _line_series(pdf, loss, chart_x, chart_y, chart_w, chart_h, right_max, (0.97, 0.55, 0.10))
    pdf.circle(x + w - 174, y + h - 32, 3, fill=(0.09, 0.48, 0.96), stroke=(0.09, 0.48, 0.96))
    pdf.text(x + w - 166, y + h - 35, "Latency", 6, color=(0.04, 0.14, 0.30))
    pdf.circle(x + w - 114, y + h - 32, 3, fill=(0.50, 0.25, 0.85), stroke=(0.50, 0.25, 0.85))
    pdf.text(x + w - 106, y + h - 35, "Jitter", 6, color=(0.04, 0.14, 0.30))
    pdf.circle(x + w - 62, y + h - 32, 3, fill=(0.97, 0.55, 0.10), stroke=(0.97, 0.55, 0.10))
    pdf.text(x + w - 54, y + h - 35, "Loss", 6, color=(0.04, 0.14, 0.30))
    _availability_timeline(pdf, quality_rows, x + 12, y + 28, w - 24, 18)
    pdf.text(x + 12, y + 48, "Service Availability", 7, bold=True, color=(0.04, 0.14, 0.30))


def _chart_grid(pdf, x, y, w, h, left_max, right_max=None):
    pdf.line(x, y, x + w, y, color=(0.80, 0.86, 0.94))
    pdf.line(x, y, x, y + h, color=(0.80, 0.86, 0.94))
    for i in range(1, 5):
        yy = y + h * i / 4
        pdf.line(x, yy, x + w, yy, color=(0.89, 0.93, 0.98), width=0.35)
        pdf.text(x - 24, yy - 2, f"{left_max * i / 4:.0f}", 5.5, color=(0.32, 0.42, 0.56))
    if right_max is not None:
        pdf.text(x + w + 5, y + h - 2, f"{right_max:.0f}%", 5.5, color=(0.32, 0.42, 0.56))


def _line_series(pdf, values, x, y, w, h, max_value, color):
    if len(values) < 2 or max_value <= 0:
        return
    last = None
    for index, value in enumerate(values):
        px = x + (w * index / max(1, len(values) - 1))
        py = y + h * max(0, min(float(value or 0), max_value)) / max_value
        if last:
            pdf.line(last[0], last[1], px, py, color=color, width=1.2)
        last = (px, py)


def _availability_timeline(pdf, quality_rows, x, y, w, h):
    rows = quality_rows or [{"status": "healthy"}]
    limit = min(len(rows), 80)
    rows = _downsample_rows(rows, limit)
    block_w = w / max(1, len(rows))
    for index, row in enumerate(rows):
        status = str(_row_value(row, "status", "healthy") or "").lower()
        color = (0.10, 0.74, 0.45)
        if status not in {"", "ok", "healthy"}:
            color = (0.95, 0.55, 0.10) if status in {"warn", "warning", "degraded"} else (0.94, 0.26, 0.29)
        pdf.rect(x + index * block_w, y, max(1.5, block_w - 0.8), h, fill=color, stroke=color)


def _speed_performance_card(pdf, speed_rows, stats, expected, x, y, w, h):
    _card(pdf, x, y, w, h)
    pdf.text(x + 12, y + h - 18, "Speed Performance", 10, bold=True, color=(0.04, 0.14, 0.30))
    pdf.text(x + 12, y + h - 32, "Download / Upload bandwidth from scheduled tests", 7, color=(0.24, 0.34, 0.50))
    chart_x, chart_y, chart_w, chart_h = x + 42, y + 82, w - 64, 92
    valid = [row for row in speed_rows if int(_row_value(row, "success", 0) or 0)]
    if len(valid) <= 10:
        _speed_bar_chart(pdf, valid, chart_x, chart_y, chart_w, chart_h)
    else:
        _speed_line_chart(pdf, valid, chart_x, chart_y, chart_w, chart_h)
    if expected.get("download_mbps"):
        max_speed = max([_num(_row_value(row, "download_mbps")) for row in valid] + [expected["download_mbps"], 1])
        yy = chart_y + chart_h * min(expected["download_mbps"], max_speed) / max_speed
        pdf.line(chart_x, yy, chart_x + chart_w, yy, color=(0.55, 0.64, 0.76), width=0.7)
    _speed_summary_strip(pdf, stats, expected, x + 12, y + 12, w - 24, 50)


def _speed_bar_chart(pdf, rows, x, y, w, h):
    if not rows:
        pdf.text(x + 10, y + h / 2, "No successful speed tests in this period.", 7, color=(0.36, 0.43, 0.54))
        return
    max_value = max([_num(_row_value(row, "download_mbps")) for row in rows] + [_num(_row_value(row, "upload_mbps")) for row in rows] + [1])
    _chart_grid(pdf, x, y, w, h, max_value)
    group_w = w / max(1, len(rows))
    for index, row in enumerate(rows):
        base_x = x + index * group_w + group_w * 0.22
        down_h = h * _num(_row_value(row, "download_mbps")) / max_value
        up_h = h * _num(_row_value(row, "upload_mbps")) / max_value
        pdf.rect(base_x, y, group_w * 0.22, down_h, fill=(0.09, 0.48, 0.96), stroke=(0.09, 0.48, 0.96))
        pdf.rect(base_x + group_w * 0.28, y, group_w * 0.22, up_h, fill=(0.31, 0.72, 0.45), stroke=(0.31, 0.72, 0.45))


def _speed_line_chart(pdf, rows, x, y, w, h):
    max_value = max([_num(_row_value(row, "download_mbps")) for row in rows] + [_num(_row_value(row, "upload_mbps")) for row in rows] + [1])
    _chart_grid(pdf, x, y, w, h, max_value)
    _line_series(pdf, [_num(_row_value(row, "download_mbps")) for row in rows], x, y, w, h, max_value, (0.09, 0.48, 0.96))
    _line_series(pdf, [_num(_row_value(row, "upload_mbps")) for row in rows], x, y, w, h, max_value, (0.31, 0.72, 0.45))


def _speed_summary_strip(pdf, stats, expected, x, y, w, h):
    _card(pdf, x, y, w, h)
    columns = [
        ("Average", _fmt_metric(stats.get("avg_download"), " Mbps"), _fmt_metric(stats.get("avg_upload"), " Mbps")),
        ("Best", _fmt_metric(stats.get("max_download"), " Mbps"), _fmt_metric(stats.get("max_upload"), " Mbps")),
        ("Lowest", _fmt_metric(stats.get("min_download"), " Mbps"), _fmt_metric(stats.get("min_upload"), " Mbps")),
    ]
    col_w = w / len(columns)
    for index, (label, down, up) in enumerate(columns):
        col_x = x + index * col_w
        if index:
            pdf.line(col_x, y + 8, col_x, y + h - 8, color=(0.84, 0.89, 0.96))
        pdf.text(col_x + 10, y + h - 16, label, 7, bold=True, color=(0.04, 0.14, 0.30))
        pdf.text(col_x + 10, y + h - 31, f"D {down}", 6.5, color=(0.09, 0.48, 0.96))
        pdf.text(col_x + 10, y + h - 43, f"U {up}", 6.5, color=(0.13, 0.64, 0.42))


def _quality_metric_cards(pdf, rollup, x, y, width):
    cards = [
        ("Latency", _fmt_metric(_row_value(rollup, "avg_latency_ms"), " ms"), _fmt_metric(_row_value(rollup, "worst_latency_ms"), " ms"), _latency_assessment(_num(_row_value(rollup, "avg_latency_ms"))), "#1473e6"),
        ("Packet Loss", _fmt_metric(_row_value(rollup, "avg_loss_pct"), "%"), _fmt_metric(_row_value(rollup, "worst_loss_pct"), "%"), _loss_assessment(_num(_row_value(rollup, "avg_loss_pct"))), "#10b981"),
        ("Jitter", _fmt_metric(_row_value(rollup, "avg_jitter_ms"), " ms"), _fmt_metric(_row_value(rollup, "worst_jitter_ms"), " ms"), _jitter_assessment(_num(_row_value(rollup, "avg_jitter_ms"))), "#7c3fd6"),
        ("DNS Response", _fmt_metric(_row_value(rollup, "avg_dns_ms"), " ms"), _fmt_metric(_row_value(rollup, "worst_dns_ms"), " ms"), _dns_assessment(_num(_row_value(rollup, "avg_dns_ms"))), "#1473e6"),
    ]
    gap = 8
    card_w = (width - gap * 3) / 4
    pdf.text(x, y + 78, "Connection Quality Metrics", 10, bold=True, color=(0.04, 0.14, 0.30))
    for index, (title, avg, worst, assessment, color_hex) in enumerate(cards):
        card_x = x + index * (card_w + gap)
        _card(pdf, card_x, y, card_w, 66)
        accent = _hex_to_rgb(color_hex)
        pdf.circle(card_x + 22, y + 43, 14, fill=tuple(1 - ((1 - c) * 0.16) for c in accent), stroke=(0.90, 0.95, 1.0))
        _quality_icon(pdf, "gauge", card_x + 22, y + 43, accent, 8)
        pdf.text(card_x + 44, y + 51, title, 7, bold=True, color=(0.04, 0.14, 0.30))
        pdf.text(card_x + 44, y + 33, f"Avg {avg}", 8, bold=True, color=(0.04, 0.10, 0.22))
        pdf.text(card_x + 44, y + 20, f"Worst {worst}", 8, bold=True, color=(0.04, 0.10, 0.22))
        pdf.text(card_x + 12, y + 7, _clip(assessment, 24), 7, color=(0.24, 0.34, 0.50))


def _quality_issues_card(pdf, issue_rows, rollup, x, y, w, h):
    _card(pdf, x, y, w, h)
    pdf.text(x + 12, y + h - 18, "Internet Quality Issues", 10, bold=True, color=(0.04, 0.14, 0.30))
    if issue_rows:
        pdf.text(x + 12, y + h - 42, f"{len(issue_rows)} degraded/outage sample(s) recorded.", 10, bold=True, color=(0.86, 0.28, 0.28))
        pdf.text(x + 12, y + h - 58, "See event detail pages for timing and metrics.", 7, color=(0.36, 0.43, 0.54))
        return
    worst_loss = _num(_row_value(rollup, "worst_loss_pct"))
    pdf.round_rect(x + 12, y + 16, w - 24, 54, fill=(0.90, 0.98, 0.94), stroke=(0.72, 0.91, 0.80))
    pdf.circle(x + 58, y + 43, 16, fill=(0.10, 0.74, 0.45), stroke=(0.10, 0.74, 0.45))
    pdf.text(x + 53, y + 37, "ok", 8, bold=True, color=(1, 1, 1))
    pdf.text(x + 88, y + 48, "No quality issues detected for this reporting period.", 9, bold=True, color=(0.04, 0.14, 0.30))
    note = "Connection remained healthy for all monitor checks."
    if worst_loss >= 5:
        note = f"No samples were classified unhealthy. A brief peak packet loss value of {worst_loss:.1f}% was observed."
    pdf.text(x + 88, y + 32, _clip(note, 72), 7, color=(0.24, 0.34, 0.50))


def _quality_insights_card(pdf, insights, x, y, w, h):
    _card(pdf, x, y, w, h)
    pdf.text(x + 12, y + h - 18, "Quality Insights", 10, bold=True, color=(0.04, 0.14, 0.30))
    row_y = y + h - 36
    for insight in insights[:5]:
        pdf.circle(x + 18, row_y + 3, 4, fill=(0.10, 0.74, 0.45), stroke=(0.10, 0.74, 0.45))
        pdf.text(x + 26, row_y, _clip(insight, 42), 7, color=(0.04, 0.14, 0.30))
        row_y -= 15


def _management_assessment_card(pdf, text, x, y, w, h):
    pdf.round_rect(x, y, w, h, fill=(0.92, 0.96, 1.0), stroke=(0.72, 0.84, 0.98))
    pdf.circle(x + 32, y + h / 2, 18, fill=(0.80, 0.90, 1.0), stroke=(0.80, 0.90, 1.0))
    _quality_icon(pdf, "bars", x + 32, y + h / 2, (0.09, 0.48, 0.96), 10)
    pdf.text(x + 66, y + h - 20, "Management Assessment", 9, bold=True, color=(0.04, 0.14, 0.30))
    for index, line in enumerate(_wrap_text(text, 100)[:3]):
        pdf.text(x + 66, y + h - 36 - index * 10, line, 7, color=(0.04, 0.14, 0.30))


def _draw_speed_history(pdf, speed_rows, expected):
    rows = []
    show_expected = bool(expected.get("download_mbps") or expected.get("upload_mbps"))
    for row in speed_rows:
        success = int(_row_value(row, "success", 0) or 0)
        down = _num(_row_value(row, "download_mbps")) if success else None
        up = _num(_row_value(row, "upload_mbps")) if success else None
        status = _speed_status(row, expected)
        base = [
            _row_value(row, "ts", ""),
            _row_value(row, "source", ""),
            _fmt_metric(_row_value(row, "latency_ms"), " ms") if success else "-",
            _fmt_metric(down, " Mbps") if success else "-",
            _fmt_metric(up, " Mbps") if success else "-",
        ]
        if show_expected:
            base.extend([
                _expected_pct_text(down, expected.get("download_mbps")) if success else "-",
                _expected_pct_text(up, expected.get("upload_mbps")) if success else "-",
            ])
        base.append(status)
        rows.append(base)
    headers = ["Date & Time", "Source", "Latency", "Download", "Upload"]
    widths = [104, 70, 55, 66, 66]
    if show_expected:
        widths = [86, 52, 44, 54, 54]
        headers.extend(["Exp Down", "Exp Up"])
        widths.extend([54, 50])
    headers.append("Status")
    widths.append(60 if not show_expected else 58)
    _table_paginated(pdf, "SPEED TEST HISTORY", headers, rows, MARGIN, 724, widths, min_y=64)
    _draw_internet_footer(pdf, len(pdf.pages))


def _draw_issue_history(pdf, issue_rows):
    rows = [[
        _row_value(row, "ts", ""),
        _row_value(row, "ts", ""),
        "-",
        _row_value(row, "status", "Issue"),
        _row_value(row, "diagnosis", "Internet quality issue recorded."),
        _fmt_metric(_row_value(row, "internet_latency_ms"), " ms"),
        _fmt_metric(_row_value(row, "internet_loss_pct"), "%"),
        _fmt_metric(_row_value(row, "jitter_ms"), " ms"),
        _fmt_metric(_row_value(row, "dns_ms"), " ms"),
    ] for row in issue_rows]
    _table_paginated(
        pdf,
        "INTERNET QUALITY EVENT DETAIL",
        ["Start", "End", "Duration", "Severity", "What Happened", "Latency", "Loss", "Jitter", "DNS"],
        rows,
        MARGIN,
        724,
        [74, 74, 50, 54, 116, 44, 38, 42, 40],
        min_y=64,
    )
    _draw_internet_footer(pdf, len(pdf.pages))


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


def _num(value, default=0.0):
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _expected_speed_config():
    try:
        c = cfg()
    except Exception:
        c = {}
    download = _num(c.get("expected_download_mbps") or c.get("wan_expected_download_mbps") or c.get("contracted_download_mbps"))
    upload = _num(c.get("expected_upload_mbps") or c.get("wan_expected_upload_mbps") or c.get("contracted_upload_mbps"))
    return {
        "download_mbps": download if download > 0 else None,
        "upload_mbps": upload if upload > 0 else None,
        "excellent_pct": 90.0,
        "acceptable_pct": 75.0,
    }


def _downtime_text(issues, samples, context):
    if not issues or not samples:
        return "0 min"
    minutes = issues
    total_seconds = int(minutes * 60)
    if total_seconds < 60:
        return f"{total_seconds}s"
    if total_seconds < 3600:
        return f"{total_seconds // 60} min"
    return f"{total_seconds // 3600}h {(total_seconds % 3600) // 60}m"


def _downsample_rows(rows, limit):
    rows = list(rows or [])
    if len(rows) <= limit:
        return rows
    step = len(rows) / float(limit)
    return [rows[min(len(rows) - 1, int(index * step))] for index in range(limit)]


def _speed_stats(rows, expected):
    valid = [row for row in rows if int(_row_value(row, "success", 0) or 0)]
    downloads = [_num(_row_value(row, "download_mbps")) for row in valid if _row_value(row, "download_mbps") is not None]
    uploads = [_num(_row_value(row, "upload_mbps")) for row in valid if _row_value(row, "upload_mbps") is not None]
    latencies = [_num(_row_value(row, "latency_ms")) for row in valid if _row_value(row, "latency_ms") is not None]
    total = len(rows)
    failed = total - len(valid)
    stats = {
        "tests": total,
        "valid": len(valid),
        "failed": failed,
        "success_pct": (len(valid) / total * 100) if total else 0,
        "avg_download": _avg(downloads),
        "min_download": min(downloads) if downloads else None,
        "max_download": max(downloads) if downloads else None,
        "avg_upload": _avg(uploads),
        "min_upload": min(uploads) if uploads else None,
        "max_upload": max(uploads) if uploads else None,
        "avg_latency": _avg(latencies),
        "min_latency": min(latencies) if latencies else None,
        "max_latency": max(latencies) if latencies else None,
        "expected_download_pct": None,
        "expected_upload_pct": None,
        "download_compliance_pct": None,
    }
    if downloads and expected.get("download_mbps"):
        expected_down = expected["download_mbps"]
        stats["expected_download_pct"] = stats["avg_download"] / expected_down * 100
        stats["download_compliance_pct"] = sum(1 for value in downloads if value >= expected_down * 0.9) / len(downloads) * 100
    if uploads and expected.get("upload_mbps"):
        stats["expected_upload_pct"] = stats["avg_upload"] / expected["upload_mbps"] * 100
    return stats


def _avg(values):
    return (sum(values) / len(values)) if values else None


def _expected_pct_text(value, expected):
    if value is None or not expected:
        return "-"
    return f"{(float(value) / float(expected) * 100):.0f}%"


def _speed_status(row, expected):
    if not int(_row_value(row, "success", 0) or 0):
        return "Failed"
    down = _num(_row_value(row, "download_mbps"))
    if expected.get("download_mbps"):
        pct = down / expected["download_mbps"] * 100
        if pct >= 90:
            return "Excellent"
        if pct >= 75:
            return "OK"
        if pct >= 50:
            return "Below Expected"
        return "Poor"
    return "OK"


def _latency_assessment(value):
    if value <= 30:
        return "Excellent response time"
    if value <= 80:
        return "Good responsiveness"
    if value <= 150:
        return "Elevated latency"
    return "Poor response time"


def _loss_assessment(value):
    if value <= 0.2:
        return "Very good quality"
    if value <= 1:
        return "Acceptable quality"
    if value <= 3:
        return "Packet loss observed"
    return "Poor packet loss"


def _jitter_assessment(value):
    if value <= 10:
        return "Stable connection"
    if value <= 30:
        return "Moderate variation"
    return "High jitter observed"


def _dns_assessment(value):
    if value <= 30:
        return "Good DNS performance"
    if value <= 100:
        return "Acceptable DNS response"
    return "Slow DNS response"


def _quality_insights(rollup, issue_rows, speed_stats, expected):
    insights = []
    issues = int(_row_value(rollup, "issue_samples", 0) or 0)
    if issues == 0:
        insights.append("No recorded outages")
    else:
        insights.append(f"Connectivity degradation occurred on {issues} sample(s)")
    if _num(_row_value(rollup, "avg_latency_ms")) <= 50:
        insights.append("Low latency and good responsiveness")
    if _num(_row_value(rollup, "avg_loss_pct")) <= 0.5:
        insights.append("Low average packet loss")
    if _num(_row_value(rollup, "worst_loss_pct")) >= 5 and issues == 0:
        insights.append("Packet-loss spike observed without outage classification")
    if speed_stats.get("valid"):
        insights.append("Speed-test performance recorded")
    if speed_stats.get("download_compliance_pct") is not None:
        insights.append(f"{speed_stats['download_compliance_pct']:.0f}% of speed tests met 90% expected download")
    if not insights:
        insights.append("Insufficient monitoring data for strong conclusions")
    return insights


def _internet_assessment(health, rollup, issue_rows, speed_stats, expected):
    label = health.get("label", "Unknown")
    issues = int(_row_value(rollup, "issue_samples", 0) or 0)
    avg_latency = _fmt_metric(_row_value(rollup, "avg_latency_ms"), " ms")
    if label in {"Excellent", "Good"} and issues == 0:
        text = f"Internet connectivity was {label.lower()} during the reporting period with no recorded outages. Average latency was {avg_latency}."
    elif issues:
        text = f"Internet connectivity was rated {label.lower()} with {issues} degraded or outage sample(s) recorded. Review event detail for timing and impact."
    else:
        text = f"Internet connectivity was rated {label.lower()}. No outage samples were recorded, but peak values should be reviewed."
    if speed_stats.get("download_compliance_pct") is not None:
        text += f" {speed_stats['download_compliance_pct']:.0f}% of valid speed tests achieved at least 90% of expected download speed."
    return text


def _draw_internet_footer(pdf, page_number):
    pdf.line(MARGIN, 42, PAGE_W - MARGIN, 42, color=(0.86, 0.91, 0.97))
    pdf.circle(MARGIN + 7, 24, 6, fill=(1, 1, 1), stroke=(0.55, 0.64, 0.76))
    pdf.text(MARGIN + 5, 21, "i", 7, bold=True, color=(0.55, 0.64, 0.76))
    footer = "Internet quality issues are recorded monitor samples where status was not healthy. Speed tests measure bandwidth on demand or schedule."
    pdf.text(MARGIN + 24, 29, _clip(footer, 104), 6.5, color=(0.36, 0.43, 0.54))
    pdf.text(PAGE_W - MARGIN - 118, 24, "Report generated by", 7, color=(0.36, 0.43, 0.54))
    pdf.text(PAGE_W - MARGIN - 30, 24, "NetSpecter", 7, bold=True, color=(0.04, 0.32, 0.70))
    pdf.text(PAGE_W / 2 - 12, 24, f"Page {page_number}", 7, color=(0.48, 0.56, 0.68))


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
