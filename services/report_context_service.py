import re
from datetime import datetime, timedelta

from netspecter_db import query
from services.ai_attribution_service import ai_attribution_summary
from services.application_classification_service import category_summary
from services.reporting_service import (
    get_activity_timeline,
    get_application_summary,
    get_destination_summary,
    get_dns_summary,
    get_internet_issue_summary,
    get_internet_quality_rollup,
    get_internet_quality_summary,
    get_speedtest_summary,
    get_top_devices,
    get_top_users,
    get_traffic_summary,
    list_applications,
    list_domains,
    parse_period,
)
from services.report_summary_service import build_rule_based_findings


def reporting_devices_for_request(args, start_time=None, end_time=None):
    selected_device_keys = _dedupe_values(args.getlist("device"))
    selected_device_lookup = args.get("device_lookup", "").strip()
    devices = _dedupe_device_rows(query(
        """
        SELECT d.ip, d.mac, COALESCE(o.name, d.name, d.ip) AS name
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        ORDER BY name COLLATE NOCASE
        LIMIT 300
        """
    ))
    selected_macs = []
    selected_ips = []
    selected_labels = []
    for value in selected_device_keys:
        matched = _match_device(devices, value)
        if matched:
            _add_selected_device(matched, selected_macs, selected_ips, selected_labels)
        else:
            selected_ips.append(value)
            selected_labels.append(value)
    matched_device = None
    if selected_device_lookup:
        matched_device = _match_device(devices, selected_device_lookup)
        if matched_device:
            _add_selected_device(matched_device, selected_macs, selected_ips, selected_labels)

    selected_ips = _dedupe_values(selected_ips + _ips_for_macs(selected_macs))
    selected_macs = _dedupe_values(selected_macs)
    selected_labels = _dedupe_values(selected_labels)
    return selected_ips, selected_macs, selected_labels, selected_device_lookup, devices, matched_device


def _match_device(devices, value):
    lookup_text = str(value or "").strip().lower()
    lookup_mac = _mac_key(lookup_text)
    if not lookup_text:
        return None
    matched = next((
        row for row in devices
        if lookup_text in {
            str(row["ip"] or "").lower(),
            str(row["mac"] or "").lower(),
            str(row["name"] or "").lower(),
        }
        or (lookup_mac and lookup_mac == _mac_key(row["mac"]))
    ), None)
    return matched or next((
        row for row in devices
        if lookup_text in str(row["ip"] or "").lower()
        or lookup_text in str(row["mac"] or "").lower()
        or lookup_text in str(row["name"] or "").lower()
        or (lookup_mac and lookup_mac in _mac_key(row["mac"]))
    ), None)


def _add_selected_device(row, selected_macs, selected_ips, selected_labels):
    mac = str(row["mac"] or "").strip()
    ip = str(row["ip"] or "").strip()
    name = str(row["name"] or "").strip()
    if mac:
        selected_macs.append(mac)
        selected_labels.append(f"{name or mac} ({mac})")
    elif ip:
        selected_ips.append(ip)
        selected_labels.append(f"{name or ip} ({ip})")


def _ips_for_macs(macs):
    mac_keys = [_mac_key(mac) for mac in macs if _mac_key(mac)]
    if not mac_keys:
        return []
    placeholders = ",".join(["?"] * len(mac_keys))
    rows = query(
        f"""
        SELECT DISTINCT ip
        FROM devices
        WHERE LOWER(REPLACE(REPLACE(mac, ':', ''), '-', '')) IN ({placeholders})
          AND ip IS NOT NULL
          AND TRIM(ip) != ''
        """,
        tuple(mac_keys),
    )
    return [str(row["ip"] or "").strip() for row in rows if str(row["ip"] or "").strip()]


def _mac_key(value):
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def _dedupe_values(values):
    output = []
    seen = set()
    for value in values or []:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            output.append(text)
    return output


def _dedupe_device_rows(rows):
    output = []
    seen = set()
    for row in rows or []:
        key = (str(row["ip"] or "").strip().lower(), str(row["mac"] or "").strip().lower(), str(row["name"] or "").strip().lower())
        ip_key = str(row["ip"] or "").strip().lower()
        mac_key = _mac_key(row["mac"])
        stable_key = mac_key or ip_key or key
        if stable_key in seen:
            continue
        seen.add(stable_key)
        output.append(row)
    return output


def build_reporting_context_from_request(args):
    requested_report_type = str(args.get("report_type") or "management").strip().lower()
    report_type = "Internet Report" if requested_report_type == "internet" else "Management Overview"
    start_value = _expand_report_start(args.get("start"))
    end_value = _expand_report_end(args.get("end"))
    period = str(args.get("period") or "30d").strip().lower()
    if period in {"7d", "7"} and not start_value and not end_value:
        end_dt = datetime.now()
        start_time, end_time = _dt_text(end_dt - timedelta(days=7)), _dt_text(end_dt)
    elif period in {"30d", "30"} and not start_value and not end_value:
        end_dt = datetime.now()
        start_time, end_time = _dt_text(end_dt - timedelta(days=30)), _dt_text(end_dt)
    else:
        start_time, end_time = parse_period(start_value, end_value)
    selected_device_ips, selected_device_macs, selected_devices, selected_device_lookup, devices, matched_device = reporting_devices_for_request(args, start_time, end_time)
    selected_application = args.get("application", "").strip()
    selected_domain = args.get("domain", "").strip()
    filters = {
        "device_ids": selected_device_ips,
        "application": selected_application,
        "domain": selected_domain,
    }
    filtered_traffic = get_traffic_summary(filters, start_time, end_time)
    overview = reporting_overview(filters, start_time, end_time, filtered_traffic)
    category_total_mb = None if selected_application else filtered_traffic["total_mb"]
    category_report = category_summary(start_time, end_time, filters, 7, category_total_mb)
    return {
        "start_time": start_time,
        "end_time": end_time,
        "selected_devices": selected_devices,
        "selected_device_ips": selected_device_ips,
        "selected_device_macs": selected_device_macs,
        "selected_device_lookup": selected_device_lookup,
        "selected_application": selected_application,
        "selected_domain": selected_domain,
        "devices": devices,
        "matched_device": matched_device,
        "filters": filters,
        "overview": overview,
        "dns_rows": get_dns_summary(filters, start_time, end_time, 8),
        "app_rows": get_application_summary(filters, start_time, end_time, 8),
        "destination_rows": get_destination_summary(filters, start_time, end_time, 8),
        "quality_rows": get_internet_quality_summary(start_time, end_time, 8),
        "internet_issue_rows": get_internet_issue_summary(start_time, end_time, 50),
        "internet_quality_rollup": get_internet_quality_rollup(start_time, end_time),
        "speedtest_rows": get_speedtest_summary(start_time, end_time, 8),
        "timeline": get_activity_timeline(filters, start_time, end_time, 50),
        "top_users": get_top_users(filters, start_time, end_time, 5),
        "top_devices": get_top_devices(filters, start_time, end_time, 8),
        "app_options": list_applications(start_time, end_time, 100),
        "domain_options": list_domains(start_time, end_time, 100),
        "category_report": category_report,
        "category_rows": category_report["rows"],
        "ai_summary": ai_attribution_summary(filters, start_time, end_time),
        "findings": build_rule_based_findings(overview),
        "selected_users": [],
        "report_type": report_type,
        "period": period if period in {"7d", "30d", "custom"} else "30d",
    }


def _dt_text(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _expand_report_start(value):
    text = str(value or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return f"{text} 00:00:00"
    return text


def _expand_report_end(value):
    text = str(value or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return f"{text} 23:59:59"
    return text


def reporting_overview(filters, start_time, end_time, traffic):
    filters = filters or {}
    device_ids = _dedupe_values(filters.get("device_ids"))
    application = str(filters.get("application") or "").strip()
    domain = str(filters.get("domain") or "").strip()

    traffic_where = ["ts BETWEEN ? AND ?"]
    traffic_params = [start_time, end_time]
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        traffic_where.append(f"ip IN ({placeholders})")
        traffic_params.extend(device_ids)

    dns_where = ["ts BETWEEN ? AND ?"]
    dns_params = [start_time, end_time]
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        dns_where.append(f"client IN ({placeholders})")
        dns_params.extend(device_ids)
    if domain:
        dns_where.append("domain LIKE ?")
        dns_params.append(f"%{domain}%")

    app_where = ["ts BETWEEN ? AND ?"]
    app_params = [start_time, end_time]
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        app_where.append(f"ip IN ({placeholders})")
        app_params.extend(device_ids)
    if application:
        app_where.append("category=?")
        app_params.append(application)

    destination_where = ["ts BETWEEN ? AND ?"]
    destination_params = [start_time, end_time]
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        destination_where.append(f"ip IN ({placeholders})")
        destination_params.extend(device_ids)
    if application:
        destination_where.append("category=?")
        destination_params.append(application)

    active_devices_sql = (
        f"SELECT COUNT(DISTINCT ip) FROM estimated_app_traffic WHERE {' AND '.join(app_where)}"
        if application else
        f"SELECT COUNT(DISTINCT ip) FROM traffic_intervals WHERE {' AND '.join(traffic_where)}"
    )
    active_devices = _scalar(active_devices_sql, tuple(app_params if application else traffic_params))

    return {
        "devices": len(device_ids) if device_ids else active_devices if application else _scalar("SELECT COUNT(*) FROM devices"),
        "active_devices": active_devices,
        "dns_total": _scalar(
            f"SELECT COUNT(*) FROM dns_querylog WHERE {' AND '.join(dns_where)}",
            tuple(dns_params),
        ),
        "dns_blocked": _scalar(
            f"SELECT COUNT(*) FROM dns_querylog WHERE blocked=1 AND {' AND '.join(dns_where)}",
            tuple(dns_params),
        ),
        "applications": _scalar(
            f"""
            SELECT COUNT(DISTINCT category)
            FROM estimated_app_traffic
            WHERE {' AND '.join(app_where)} AND category IS NOT NULL AND category != ''
            """,
            tuple(app_params),
        ),
        "unique_destinations": _scalar(
            f"""
            SELECT COUNT(DISTINCT remote_ip)
            FROM remote_traffic_intervals
            WHERE {' AND '.join(destination_where)}
            """,
            tuple(destination_params),
        ),
        "ids_alerts": _scalar("SELECT COUNT(*) FROM ids_events WHERE event_type='alert' AND ts BETWEEN ? AND ?", (start_time, end_time)),
        "open_incidents": _scalar(
            """
            SELECT COUNT(*)
            FROM security_incidents
            WHERE status NOT IN ('resolved', 'closed') AND last_event_ts BETWEEN ? AND ?
            """,
            (start_time, end_time),
        ),
        "internet_issues": _scalar(
            """
            SELECT COUNT(*)
            FROM internet_quality
            WHERE status NOT IN ('ok', 'healthy') AND ts BETWEEN ? AND ?
            """,
            (start_time, end_time),
        ),
        "downloaded_mb": float(traffic.get("downloaded_mb") or 0),
        "uploaded_mb": float(traffic.get("uploaded_mb") or 0),
        "total_mb": float(traffic.get("total_mb") or 0),
    }


def _scalar(sql, params=()):
    rows = query(sql, params)
    if not rows:
        return 0
    row = rows[0]
    try:
        return int(row[0] or 0)
    except Exception:
        return int(next(iter(row), 0) or 0)
