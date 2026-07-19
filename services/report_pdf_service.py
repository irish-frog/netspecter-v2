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

    pdf.rect(0, 758, PAGE_W, 84, fill=(0.03, 0.08, 0.15), stroke=(0.03, 0.08, 0.15))
    pdf.rect(0, 754, PAGE_W, 4, fill=(0.09, 0.48, 0.96), stroke=(0.09, 0.48, 0.96))
    report_title = str(context.get("report_type") or "Management Overview").strip()
    if not report_title.lower().endswith("report"):
        report_title += " Report"
    pdf.text(MARGIN, 808, report_title, 20, bold=True, color=(1, 1, 1))
    pdf.text(MARGIN, 787, _report_scope(context), 9, color=(0.73, 0.82, 0.94))
    pdf.text(MARGIN, 771, f"{context['start_time']} to {context['end_time']}", 8, color=(0.73, 0.82, 0.94))
    pdf.text(470, 808, "Executive Report", 9, bold=True, color=(0.73, 0.82, 0.94))

    stats = [
        ("Total Traffic", _fmt_mb(overview.get("total_mb", 0)), "Across selected period"),
        ("Upload", _fmt_mb(overview.get("uploaded_mb", 0)), "Outbound traffic"),
        ("Download", _fmt_mb(overview.get("downloaded_mb", 0)), "Inbound traffic"),
        ("Active Devices", f"{overview.get('active_devices', 0):,}", f"{overview.get('devices', 0):,} monitored"),
        ("Applications", f"{overview.get('applications', 0):,}", "Detected categories"),
        ("Destinations", f"{overview.get('unique_destinations', 0):,}", "Unique endpoints"),
    ]
    _kpi_cards(pdf, stats, 704)

    coverage = float(category_report.get("classification_coverage_pct") or 0)
    pdf.round_rect(MARGIN, 574, 511, 126, fill=(0.98, 0.99, 1.0), stroke=(0.82, 0.88, 0.95))
    pdf.text(MARGIN + 14, 678, "Application Usage", 13, bold=True, color=(0.05, 0.12, 0.22))
    pdf.text(MARGIN + 14, 661, f"{coverage:.1f}% of total traffic is classified by application.", 8, color=(0.36, 0.43, 0.54))
    _application_usage_summary(pdf, category_rows, MARGIN + 14, 641, 483)

    _status_panel(pdf, findings, MARGIN, 438, 246, 116)
    _ai_panel(pdf, ai_summary, 307, 438, 246, 116)

    y = 414
    y = _category_table(pdf, category_rows, MARGIN, y)
    y = _table(
        pdf,
        "Top Devices",
        ["Device", "MAC", "IP", "Total", "Up", "Down"],
        [
            [
                _row_value(row, "name", ""),
                _row_value(row, "mac", ""),
                _row_value(row, "ip", ""),
                _fmt_mb(_row_value(row, "total_mb", 0)),
                _fmt_mb(_row_value(row, "uploaded_mb", 0)),
                _fmt_mb(_row_value(row, "downloaded_mb", 0)),
            ]
            for row in (context.get("top_devices") or [])[:7]
        ],
        MARGIN,
        y - 6,
        [108, 98, 72, 74, 64, 64],
    )

    pdf.line(MARGIN, 42, PAGE_W - MARGIN, 42, color=(0.86, 0.91, 0.97))
    pdf.text(MARGIN, 28, "Limitations: identity depends on maintained labels and device assignments; encrypted, CDN, and shared-cloud traffic may not always identify the exact application or person.", 7, color=(0.36, 0.43, 0.54))


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


def _kpi_cards(pdf, stats, y):
    for index, (label, value, detail) in enumerate(stats):
        x = MARGIN + (index % 3) * 171
        card_y = y - (index // 3) * 58
        pdf.round_rect(x, card_y, 156, 44, fill=(0.96, 0.98, 1.0), stroke=(0.80, 0.87, 0.95))
        pdf.text(x + 10, card_y + 29, label, 7, bold=True, color=(0.36, 0.43, 0.54))
        pdf.text(x + 10, card_y + 13, value, 13, bold=True, color=(0.05, 0.12, 0.22))
        pdf.text(x + 88, card_y + 14, _clip(detail, 18), 6, color=(0.48, 0.56, 0.68))


def _status_panel(pdf, findings, x, y, w, h):
    rating = str(findings.get("rating", "Low") or "Low")
    tone = (0.13, 0.64, 0.42)
    if rating.lower() == "watch":
        tone = (0.86, 0.53, 0.16)
    elif rating.lower() in {"moderate", "high"}:
        tone = (0.86, 0.28, 0.28)
    pdf.round_rect(x, y, w, h, fill=(0.98, 0.99, 1.0), stroke=(0.82, 0.88, 0.95))
    pdf.text(x + 12, y + h - 20, "Usage Status", 11, bold=True, color=(0.05, 0.12, 0.22))
    pdf.text(x + 12, y + h - 43, f"{rating} ({findings.get('score', 0)} points)", 16, bold=True, color=tone)
    reasons = findings.get("reasons") or []
    if not reasons:
        pdf.text(x + 12, y + h - 63, "No notable usage concerns detected.", 8, color=(0.36, 0.43, 0.54))
    for offset, reason in enumerate(reasons[:3]):
        pdf.text(x + 12, y + h - 64 - (offset * 14), f"- {_clip(reason, 45)}", 8, color=(0.36, 0.43, 0.54))


def _ai_panel(pdf, ai_summary, x, y, w, h):
    pdf.round_rect(x, y, w, h, fill=(0.98, 0.99, 1.0), stroke=(0.82, 0.88, 0.95))
    pdf.text(x + 12, y + h - 20, "AI Services", 11, bold=True, color=(0.05, 0.12, 0.22))
    if not ai_summary.get("services_detected"):
        pdf.text(x + 12, y + h - 43, "No AI services detected", 12, bold=True, color=(0.05, 0.12, 0.22))
        pdf.text(x + 12, y + h - 62, "No matching DNS or traffic evidence in this period.", 8, color=(0.36, 0.43, 0.54))
        return
    services = ai_summary.get("services") or []
    top = next((row for row in services if float(row.get("attributed_mb") or 0) > 0), services[0] if services else {})
    pdf.text(x + 12, y + h - 43, _fmt_mb(ai_summary.get("attributed_mb") or 0), 16, bold=True, color=(0.43, 0.32, 0.86))
    pdf.text(x + 92, y + h - 39, "attributed AI traffic", 8, color=(0.36, 0.43, 0.54))
    pdf.text(x + 12, y + h - 63, f"{ai_summary.get('services_detected', 0)} services detected, {len(ai_summary.get('devices') or [])} devices", 8, color=(0.36, 0.43, 0.54))
    pdf.text(x + 12, y + h - 80, f"Top service: {_clip(top.get('service', 'Unknown'), 28)}", 8, bold=True, color=(0.05, 0.12, 0.22))
    pdf.text(x + 12, y + h - 96, f"Coverage: {ai_summary.get('attribution_coverage', 'Unknown')}", 8, color=(0.36, 0.43, 0.54))


def _application_usage_summary(pdf, category_rows, x, y, width):
    rows = [row for row in category_rows if _row_value(row, "category") != "Unclassified / Other Network Traffic"][:5]
    if not rows:
        pdf.text(x, y - 10, "No classified application traffic found for this period.", 8, color=(0.36, 0.43, 0.54))
        return
    max_pct = max(float(_row_value(row, "share_total_pct", 0) or 0) for row in rows) or 1.0
    pdf.text(x, y, "Category", 7, bold=True, color=(0.36, 0.43, 0.54))
    pdf.text(x + 310, y, "% Total", 7, bold=True, color=(0.36, 0.43, 0.54))
    pdf.text(x + 395, y, "Traffic", 7, bold=True, color=(0.36, 0.43, 0.54))
    row_y = y - 18
    for row in rows:
        category = str(_row_value(row, "category", ""))
        pct = float(_row_value(row, "share_total_pct", 0) or 0)
        traffic = _fmt_mb(_row_value(row, "total_mb", 0))
        color = _hex_to_rgb(_row_value(row, "color", "#64748b"))
        pdf.rect(x, row_y - 2, 220, 6, fill=(0.91, 0.95, 0.99), stroke=(0.91, 0.95, 0.99))
        pdf.rect(x, row_y - 2, max(2, 220 * (pct / max_pct)), 6, fill=color, stroke=color)
        pdf.text(x, row_y + 7, _clip(category, 38), 8, bold=True, color=(0.05, 0.12, 0.22))
        pdf.text(x + 310, row_y + 2, f"{pct:.1f}%", 8, bold=True, color=(0.05, 0.12, 0.22))
        pdf.text(x + 395, row_y + 2, traffic, 8, color=(0.36, 0.43, 0.54))
        row_y -= 17


def _category_table(pdf, category_rows, x, y):
    rows = [row for row in category_rows if _row_value(row, "category") != "Unclassified / Other Network Traffic"][:7]
    table_rows = []
    for row in rows:
        apps = _row_value(row, "application_names", []) or []
        table_rows.append([
            _row_value(row, "category", ""),
            _fmt_mb(_row_value(row, "total_mb", 0)),
            f"{float(_row_value(row, 'share_total_pct', 0) or 0):.1f}%",
            _clip(", ".join(str(app) for app in apps[:4]), 32),
        ])
    return _table(
        pdf,
        "Category Detail",
        ["Category", "Traffic", "% Total", "Top Applications"],
        table_rows,
        x,
        y,
        [168, 80, 62, 200],
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


def _draw_pie(pdf, cx, cy, radius, rows):
    start = -90.0
    total = 0.0
    for row in rows:
        if _row_value(row, "category") == "Unclassified / Other Network Traffic":
            continue
        pct = max(0.0, float(_row_value(row, "share_classified_pct", _row_value(row, "share_total_pct", 0)) or 0))
        if pct <= 0:
            continue
        end = min(270.0, start + pct * 3.6)
        pdf.wedge(cx, cy, radius, start, end, fill=_hex_to_rgb(_row_value(row, "color", "#64748b")))
        start = end
        total += pct
        if total >= 100:
            break
    pdf.circle(cx, cy, 31, fill=(1, 1, 1), stroke=(1, 1, 1))
    pdf.text(cx - 29, cy + 4, "Total", 8, bold=True, color=(0.05, 0.12, 0.22))
    pdf.text(cx - 35, cy - 9, "Network", 8, color=(0.36, 0.43, 0.54))


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


def _pdf_escape(text):
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class _Pdf:
    def __init__(self):
        self.ops = []

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
        stream = "\n".join(self.ops).encode("latin-1", "replace")
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
        ]
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
