import csv
import io
import re


AI_PRIVACY_WARNING = (
    "This report may contain client, user, device, domain, and network information. "
    "Review the content and your client's data-handling requirements before pasting it "
    "into an external AI service."
)


AI_PROMPT = """You are assisting an IT security consultant.

Rewrite the following NetSpecter report into a professional management summary.

Requirements:
- Use clear, non-technical language.
- Do not exaggerate risks.
- Do not invent facts.
- Distinguish confirmed findings from possible concerns.
- Highlight significant security events, unusual activity, internet-performance problems, and recurring issues.
- Provide practical recommendations.
- State when the available evidence is insufficient to reach a conclusion.
- Keep usernames, device names, domains, IP addresses, dates, and statistics accurate.
- Do not claim that a user intentionally performed an action unless the evidence proves it.

NetSpecter report:
"""


def csv_text(headers, rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(headers)
    for row in rows:
        writer.writerow([safe_csv_value(_row_value(row, header, "")) for header in headers])
    return out.getvalue()


def safe_csv_value(value):
    text = str(value if value is not None else "")
    if text[:1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


def safe_filename(prefix, start_time, end_time, extension):
    raw = f"{prefix}_{str(start_time)[:10]}_to_{str(end_time)[:10]}.{extension}"
    return re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-").lower()


def structured_report_text(context, mask_options=None):
    mask_options = mask_options or {}
    lines = []
    overview = context["overview"]
    findings = context["findings"]
    start_time = context["start_time"]
    end_time = context["end_time"]
    selected_devices = context.get("selected_devices") or []
    selected_users = context.get("selected_users") or []
    category_report = context.get("category_report") or {}

    lines.append("# NetSpecter Client Overview Report")
    lines.append("")
    lines.append(f"Reporting period: {start_time} to {end_time}")
    if context.get("selected_application"):
        lines.append(f"Application filter: {context.get('selected_application')}")
    if context.get("selected_domain"):
        lines.append(f"Site/domain filter: {context.get('selected_domain')}")
    lines.append(f"Selected users: {', '.join(selected_users) if selected_users else 'All or unassigned users'}")
    lines.append(f"Selected devices: {', '.join(_mask_list(selected_devices, mask_options, 'device')) if selected_devices else 'All devices'}")
    lines.append("")
    lines.append("## Summary Statistics")
    lines.append(f"- Devices monitored: {overview.get('devices', 0)}")
    lines.append(f"- Active devices: {overview.get('active_devices', 0)}")
    lines.append(f"- DNS requests: {overview.get('dns_total', 0)}")
    lines.append(f"- Total traffic MB: {overview.get('total_mb', 0):.2f}")
    lines.append(f"- Upload traffic MB: {overview.get('uploaded_mb', 0):.2f}")
    lines.append(f"- Download traffic MB: {overview.get('downloaded_mb', 0):.2f}")
    lines.append(f"- Applications detected: {overview.get('applications', 0)}")
    lines.append(f"- Unique destinations: {overview.get('unique_destinations', 0)}")
    lines.append("")
    if category_report:
        lines.append("## Application Classification Coverage")
        lines.append(
            f"{category_report.get('classification_coverage_pct', 0)}% "
            f"({float(category_report.get('classified_application_mb') or 0):.2f} MB of "
            f"{float(category_report.get('total_network_mb') or 0):.2f} MB classified by application)"
        )
        lines.append("")
    ai_summary = context.get("ai_summary") or {}
    if ai_summary.get("services_detected"):
        lines.append("## AI Services Summary")
        lines.append(f"- Services detected: {ai_summary.get('services_detected', 0)}")
        lines.append(f"- Services with confidently attributed traffic: {ai_summary.get('services_with_attributed_traffic', 0)}")
        lines.append(f"- Confidently attributed AI traffic MB: {float(ai_summary.get('attributed_mb') or 0):.2f}")
        lines.append(f"- AI devices: {len(ai_summary.get('devices') or [])}")
        lines.append(f"- Attribution coverage: {ai_summary.get('attribution_coverage', 'Unknown')}")
        for service in (ai_summary.get("services") or [])[:10]:
            lines.append(
                f"- {service.get('service')}: Detected: {'Yes' if service.get('service_detected') else 'No'}; "
                f"Detection confidence: {service.get('service_detection_confidence')}; "
                f"Confidently attributed traffic: {float(service.get('attributed_mb') or 0):.2f} MB; "
                f"DNS-correlated traffic evidence: {float(service.get('dns_correlated_mb') or 0):.2f} MB; "
                f"Traffic attribution status: {service.get('traffic_attribution_status')}; "
                f"Evidence: {service.get('evidence_summary')}; "
                "Limitation: actual usage may be higher because some encrypted, CDN, shared-cloud, or long-lived traffic could not be confidently assigned."
            )
        lines.append("")
    lines.append("## Usage Status")
    lines.append(f"{findings.get('rating', 'Low')} ({findings.get('score', 0)} points)")
    for reason in findings.get("reasons", []):
        lines.append(f"- {reason}")
    lines.append("")
    lines.append("## Findings")
    for item in findings.get("findings", []):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Recommendations")
    for item in findings.get("recommendations", []):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Application Usage by Category")
    for row in context.get("category_rows", [])[:8]:
        apps = _row_value(row, "application_names", []) or []
        app_text = f" Apps: {', '.join(str(app) for app in apps[:10])}." if apps else ""
        lines.append(
            f"- {_row_value(row, 'category', '')}: "
            f"{float(_row_value(row, 'total_mb', 0) or 0):.2f} MB attributed traffic, "
            f"{_row_value(row, 'share_total_pct', 0)}% of total network traffic, "
            f"{_row_value(row, 'share_classified_pct', 0)}% of classified application traffic."
            f"{app_text}"
        )
    lines.append("")
    top_users = context.get("top_users", [])[:10]
    if top_users:
        lines.append("## Top Assigned Users")
        for row in top_users:
            label = _mask_value(_row_value(row, "user_label", ""), mask_options, "device")
            total_mb = float(_row_value(row, "total_mb", 0) or 0)
            requests = _row_value(row, "requests", "")
            if requests != "":
                lines.append(f"- {label}: {requests} DNS requests, { _row_value(row, 'devices', 0) } device(s)")
            else:
                lines.append(f"- {label}: {total_mb:.2f} MB total, {_row_value(row, 'devices', 0)} device(s)")
        lines.append("")
    lines.append("## Top Devices")
    for row in context.get("top_devices", [])[:10]:
        name = _mask_value(_row_value(row, "name", ""), mask_options, "device")
        total_mb = float(_row_value(row, "total_mb", 0) or 0)
        lines.append(f"- {name}: {total_mb:.2f} MB total")
    lines.append("")
    lines.append("## Data Limitations")
    lines.append("- User identity is based on technician-maintained labels and device assignments where configured.")
    lines.append("- DNS, application, destination, and traffic data may not always identify the actual logged-in person.")
    lines.append("- Timeline highlights are limited; detailed exports should be used for raw event review.")
    return "\n".join(lines).strip() + "\n"


def ai_prompt_text(context, mask_options=None):
    return AI_PRIVACY_WARNING + "\n\n" + AI_PROMPT + "\n" + structured_report_text(context, mask_options)


def _mask_list(values, mask_options, kind):
    return [_mask_value(value, mask_options, kind) for value in values]


def _row_value(row, key, default=""):
    if row is None:
        return default
    if hasattr(row, "get"):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default


def _mask_value(value, mask_options, kind):
    text = str(value or "")
    if not text:
        return ""
    if kind == "device" and mask_options.get("mask_devices"):
        return "DEVICE"
    if kind == "domain" and mask_options.get("mask_domains"):
        return "DOMAIN"
    if kind == "ip" and mask_options.get("mask_ips"):
        return "IP_ADDRESS"
    return text
