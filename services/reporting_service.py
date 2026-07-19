import time
from datetime import datetime, timedelta

from netspecter_db import query


SLOW_QUERY_MS = 500
DEFAULT_LIMIT = 100
MAX_LIMIT = 500


def parse_period(start_value=None, end_value=None):
    end = _parse_dt(end_value) or datetime.now()
    start = _parse_dt(start_value) or (end - timedelta(days=1))
    if start > end:
        start, end = end, start
    return _dt_text(start), _dt_text(end)


def get_site_overview(start_time, end_time):
    return {
        "devices": _scalar("SELECT COUNT(*) FROM devices"),
        "active_devices": _scalar(
            """
            SELECT COUNT(DISTINCT ip)
            FROM traffic_intervals
            WHERE ts BETWEEN ? AND ?
            """,
            (start_time, end_time),
        ),
        "dns_total": _scalar(
            "SELECT COUNT(*) FROM dns_querylog WHERE ts BETWEEN ? AND ?",
            (start_time, end_time),
        ),
        "dns_blocked": _scalar(
            "SELECT COUNT(*) FROM dns_querylog WHERE blocked=1 AND ts BETWEEN ? AND ?",
            (start_time, end_time),
        ),
        "applications": _scalar(
            """
            SELECT COUNT(DISTINCT category)
            FROM estimated_app_traffic
            WHERE ts BETWEEN ? AND ? AND category IS NOT NULL AND category != ''
            """,
            (start_time, end_time),
        ),
        "unique_destinations": _scalar(
            """
            SELECT COUNT(DISTINCT remote_ip)
            FROM remote_traffic_intervals
            WHERE ts BETWEEN ? AND ?
            """,
            (start_time, end_time),
        ),
        "ids_alerts": _scalar(
            """
            SELECT COUNT(*)
            FROM ids_events
            WHERE event_type='alert' AND ts BETWEEN ? AND ?
            """,
            (start_time, end_time),
        ),
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
        **get_traffic_summary({}, start_time, end_time),
    }


def get_device_activity(device_ids, start_time, end_time, limit=DEFAULT_LIMIT):
    ids = _clean_list(device_ids)
    if not ids:
        return []
    placeholders = ",".join(["?"] * len(ids))
    return _timed_query(
        f"""
        SELECT
            COALESCE(o.name, d.name, t.name, t.ip) AS name,
            t.ip,
            d.mac,
            SUM(t.downloaded_mb) AS downloaded_mb,
            SUM(t.uploaded_mb) AS uploaded_mb,
            SUM(t.total_mb) AS total_mb,
            MAX(t.ts) AS last_seen
        FROM traffic_intervals t
        LEFT JOIN (
            SELECT ip, MAX(name) AS name, MAX(mac) AS mac
            FROM devices
            GROUP BY ip
        ) d ON d.ip=t.ip
        LEFT JOIN (
            SELECT ip, MAX(name) AS name
            FROM device_overrides
            GROUP BY ip
        ) o ON o.ip=t.ip
        WHERE t.ip IN ({placeholders}) AND t.ts BETWEEN ? AND ?
        GROUP BY t.ip
        ORDER BY total_mb DESC
        LIMIT ?
        """,
        (*ids, start_time, end_time, _limit(limit)),
        "device_activity",
    )


def get_top_users(filters, start_time, end_time, limit=5):
    filters = filters or {}
    app = str(filters.get("application") or "").strip()
    domain = str(filters.get("domain") or "").strip()
    device_ids = _clean_list(filters.get("device_ids"))

    assignment_clause = "AND a.assigned_from <= ? AND (a.assigned_to IS NULL OR a.assigned_to='' OR a.assigned_to >= ?)"
    assignment_params = [end_time, start_time]
    device_clause = ""
    device_params = []
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        device_clause = f"AND a.device_ip IN ({placeholders})"
        device_params.extend(device_ids)

    if app:
        return _timed_query(
            f"""
            SELECT
                u.display_name AS user_label,
                COUNT(DISTINCT t.ip) AS devices,
                SUM(t.downloaded_mb) AS downloaded_mb,
                SUM(t.uploaded_mb) AS uploaded_mb,
                SUM(t.total_mb) AS total_mb,
                MAX(t.ts) AS last_seen
            FROM user_device_assignments a
            JOIN user_labels u ON u.id=a.user_id
            JOIN estimated_app_traffic t ON t.ip=a.device_ip
            WHERE u.active=1
              AND u.display_name IS NOT NULL
              AND TRIM(u.display_name) != ''
              {assignment_clause}
              AND t.ts BETWEEN ? AND ?
              AND t.category=?
              {device_clause}
            GROUP BY u.id, u.display_name
            ORDER BY total_mb DESC
            LIMIT ?
            """,
            (*assignment_params, start_time, end_time, app, *device_params, _limit(limit)),
            "top_users_application",
        )

    if domain:
        dns_device_clause = ""
        dns_params = []
        if device_ids:
            placeholders = ",".join(["?"] * len(device_ids))
            dns_device_clause = f"AND a.device_ip IN ({placeholders})"
            dns_params.extend(device_ids)
        return _timed_query(
            f"""
            SELECT
                u.display_name AS user_label,
                COUNT(DISTINCT q.client) AS devices,
                0 AS downloaded_mb,
                0 AS uploaded_mb,
                0 AS total_mb,
                COUNT(*) AS requests,
                MAX(q.ts) AS last_seen
            FROM user_device_assignments a
            JOIN user_labels u ON u.id=a.user_id
            JOIN dns_querylog q ON q.client=a.device_ip
            WHERE u.active=1
              AND u.display_name IS NOT NULL
              AND TRIM(u.display_name) != ''
              {assignment_clause}
              AND q.ts BETWEEN ? AND ?
              AND q.domain LIKE ?
              {dns_device_clause}
            GROUP BY u.id, u.display_name
            ORDER BY requests DESC
            LIMIT ?
            """,
            (*assignment_params, start_time, end_time, f"%{domain}%", *dns_params, _limit(limit)),
            "top_users_domain",
        )

    return _timed_query(
        f"""
        SELECT
            u.display_name AS user_label,
            COUNT(DISTINCT t.ip) AS devices,
            SUM(t.downloaded_mb) AS downloaded_mb,
            SUM(t.uploaded_mb) AS uploaded_mb,
            SUM(t.total_mb) AS total_mb,
            MAX(t.ts) AS last_seen
        FROM user_device_assignments a
        JOIN user_labels u ON u.id=a.user_id
        JOIN traffic_intervals t ON t.ip=a.device_ip
        WHERE u.active=1
          AND u.display_name IS NOT NULL
          AND TRIM(u.display_name) != ''
          {assignment_clause}
          AND t.ts BETWEEN ? AND ?
          {device_clause}
        GROUP BY u.id, u.display_name
        ORDER BY total_mb DESC
        LIMIT ?
        """,
        (*assignment_params, start_time, end_time, *device_params, _limit(limit)),
        "top_users",
    )


def get_top_devices(filters, start_time, end_time, limit=10):
    filters = filters or {}
    application = str(filters.get("application") or "").strip()
    domain = str(filters.get("domain") or "").strip()
    if application:
        where, params = _filter_clause(filters, {"device_ids": "t.ip", "application": "t.category"})
        return _timed_query(
            f"""
            SELECT
                COALESCE(o.name, d.name, t.ip) AS name,
                t.ip,
                d.mac,
                SUM(t.downloaded_mb) AS downloaded_mb,
                SUM(t.uploaded_mb) AS uploaded_mb,
                SUM(t.total_mb) AS total_mb,
                MAX(t.ts) AS last_seen
            FROM estimated_app_traffic t
            LEFT JOIN (
                SELECT ip, MAX(name) AS name, MAX(mac) AS mac
                FROM devices
                GROUP BY ip
            ) d ON d.ip=t.ip
            LEFT JOIN (
                SELECT ip, MAX(name) AS name
                FROM device_overrides
                GROUP BY ip
            ) o ON o.ip=t.ip
            WHERE t.ts BETWEEN ? AND ? {where}
            GROUP BY t.ip
            ORDER BY total_mb DESC
            LIMIT ?
            """,
            (start_time, end_time, *params, _limit(limit)),
            "top_devices_application",
        )
    if domain:
        where, params = _filter_clause(filters, {"device_ids": "q.client"})
        return _timed_query(
            f"""
            SELECT
                COALESCE(o.name, d.name, q.client) AS name,
                q.client AS ip,
                d.mac,
                0 AS downloaded_mb,
                0 AS uploaded_mb,
                0 AS total_mb,
                MAX(q.ts) AS last_seen,
                COUNT(*) AS requests
            FROM dns_querylog q
            LEFT JOIN (
                SELECT ip, MAX(name) AS name, MAX(mac) AS mac
                FROM devices
                GROUP BY ip
            ) d ON d.ip=q.client
            LEFT JOIN (
                SELECT ip, MAX(name) AS name
                FROM device_overrides
                GROUP BY ip
            ) o ON o.ip=q.client
            WHERE q.ts BETWEEN ? AND ? AND q.domain LIKE ? {where}
            GROUP BY q.client
            ORDER BY requests DESC
            LIMIT ?
            """,
            (start_time, end_time, f"%{domain}%", *params, _limit(limit)),
            "top_devices_domain",
        )

    where, params = _filter_clause(filters, {"device_ids": "t.ip"})
    return _timed_query(
        f"""
        SELECT
            COALESCE(o.name, d.name, t.name, t.ip) AS name,
            t.ip,
            d.mac,
            SUM(t.downloaded_mb) AS downloaded_mb,
            SUM(t.uploaded_mb) AS uploaded_mb,
            SUM(t.total_mb) AS total_mb,
            MAX(t.ts) AS last_seen
        FROM traffic_intervals t
        LEFT JOIN (
            SELECT ip, MAX(name) AS name, MAX(mac) AS mac
            FROM devices
            GROUP BY ip
        ) d ON d.ip=t.ip
        LEFT JOIN (
            SELECT ip, MAX(name) AS name
            FROM device_overrides
            GROUP BY ip
        ) o ON o.ip=t.ip
        WHERE t.ts BETWEEN ? AND ? {where}
        GROUP BY t.ip
        ORDER BY total_mb DESC
        LIMIT ?
        """,
        (start_time, end_time, *params, _limit(limit)),
        "top_devices",
    )


def get_user_activity(user_ids, start_time, end_time):
    return []


def get_dns_summary(filters, start_time, end_time, limit=DEFAULT_LIMIT):
    where, params = _filter_clause(filters, {"device_ids": "client", "application": "category"})
    return _timed_query(
        f"""
        SELECT domain, category, blocked, COUNT(*) AS requests, COUNT(DISTINCT client) AS clients
        FROM dns_querylog
        WHERE ts BETWEEN ? AND ? {where}
        GROUP BY domain, category, blocked
        ORDER BY requests DESC
        LIMIT ?
        """,
        (start_time, end_time, *params, _limit(limit)),
        "dns_summary",
    )


def get_application_summary(filters, start_time, end_time, limit=DEFAULT_LIMIT):
    where, params = _filter_clause(filters, {"device_ids": "ip", "application": "category"})
    return _timed_query(
        f"""
        SELECT category, SUM(downloaded_mb) AS downloaded_mb, SUM(uploaded_mb) AS uploaded_mb,
               SUM(total_mb) AS total_mb, COUNT(DISTINCT ip) AS devices
        FROM estimated_app_traffic
        WHERE ts BETWEEN ? AND ? {where}
        GROUP BY category
        ORDER BY total_mb DESC
        LIMIT ?
        """,
        (start_time, end_time, *params, _limit(limit)),
        "application_summary",
    )


def get_destination_summary(filters, start_time, end_time, limit=DEFAULT_LIMIT):
    filters = filters or {}
    domain = str(filters.get("domain") or "").strip()
    if domain:
        where, params = _filter_clause(filters, {"device_ids": "r.ip"})
        return _timed_query(
            f"""
            SELECT r.remote_ip, COALESCE(l.country, '') AS country, r.category,
                   SUM(r.downloaded_mb) AS downloaded_mb, SUM(r.uploaded_mb) AS uploaded_mb,
                   SUM(r.total_mb) AS total_mb, COUNT(DISTINCT r.ip) AS devices
            FROM remote_traffic_intervals r
            JOIN dns_resolved_ips dr ON dr.remote_ip=r.remote_ip
            LEFT JOIN remote_ip_locations l ON l.remote_ip=r.remote_ip
            WHERE r.ts BETWEEN ? AND ? AND dr.domain LIKE ? {where}
            GROUP BY r.remote_ip, l.country, r.category
            ORDER BY total_mb DESC
            LIMIT ?
            """,
            (start_time, end_time, f"%{domain}%", *params, _limit(limit)),
            "destination_summary_domain",
        )

    where, params = _filter_clause(filters, {"device_ids": "r.ip", "application": "r.category"})
    return _timed_query(
        f"""
        SELECT r.remote_ip, COALESCE(l.country, '') AS country, r.category,
               SUM(r.downloaded_mb) AS downloaded_mb, SUM(r.uploaded_mb) AS uploaded_mb,
               SUM(r.total_mb) AS total_mb, COUNT(DISTINCT r.ip) AS devices
        FROM remote_traffic_intervals r
        LEFT JOIN remote_ip_locations l ON l.remote_ip=r.remote_ip
        WHERE r.ts BETWEEN ? AND ? {where}
        GROUP BY r.remote_ip, l.country, r.category
        ORDER BY total_mb DESC
        LIMIT ?
        """,
        (start_time, end_time, *params, _limit(limit)),
        "destination_summary",
    )


def get_traffic_summary(filters, start_time, end_time):
    filters = filters or {}
    application = str(filters.get("application") or "").strip()
    if application:
        where, params = _filter_clause(filters, {"device_ids": "ip", "application": "category"})
        rows = _timed_query(
            f"""
            SELECT SUM(downloaded_mb) AS downloaded_mb, SUM(uploaded_mb) AS uploaded_mb,
                   SUM(total_mb) AS total_mb
            FROM estimated_app_traffic
            WHERE ts BETWEEN ? AND ? {where}
            """,
            (start_time, end_time, *params),
            "traffic_summary_application",
        )
        row = rows[0] if rows else {}
        return {
            "downloaded_mb": float(row["downloaded_mb"] or 0) if row else 0,
            "uploaded_mb": float(row["uploaded_mb"] or 0) if row else 0,
            "total_mb": float(row["total_mb"] or 0) if row else 0,
        }

    where, params = _filter_clause(filters, {"device_ids": "ip"})
    rows = _timed_query(
        f"""
        SELECT SUM(downloaded_mb) AS downloaded_mb, SUM(uploaded_mb) AS uploaded_mb,
               SUM(total_mb) AS total_mb
        FROM traffic_intervals
        WHERE ts BETWEEN ? AND ? {where}
        """,
        (start_time, end_time, *params),
        "traffic_summary",
    )
    row = rows[0] if rows else {}
    return {
        "downloaded_mb": float(row["downloaded_mb"] or 0) if row else 0,
        "uploaded_mb": float(row["uploaded_mb"] or 0) if row else 0,
        "total_mb": float(row["total_mb"] or 0) if row else 0,
    }


def list_applications(start_time, end_time, limit=100):
    return _timed_query(
        """
        SELECT category, SUM(total_mb) AS total_mb
        FROM estimated_app_traffic
        WHERE ts BETWEEN ? AND ? AND category IS NOT NULL AND category != ''
        GROUP BY category
        ORDER BY total_mb DESC
        LIMIT ?
        """,
        (start_time, end_time, _limit(limit)),
        "list_applications",
    )


def list_domains(start_time, end_time, limit=100):
    return _timed_query(
        """
        SELECT domain, COUNT(*) AS requests
        FROM dns_querylog
        WHERE ts BETWEEN ? AND ? AND domain IS NOT NULL AND domain != ''
        GROUP BY domain
        ORDER BY requests DESC
        LIMIT ?
        """,
        (start_time, end_time, _limit(limit)),
        "list_domains",
    )


def get_ids_summary(filters, start_time, end_time, limit=DEFAULT_LIMIT):
    where, params = _filter_clause(filters, {"device_ids": "src_ip"})
    return _timed_query(
        f"""
        SELECT severity, signature, COUNT(*) AS alerts, COUNT(DISTINCT src_ip) AS devices
        FROM ids_events
        WHERE event_type='alert' AND ts BETWEEN ? AND ? {where}
        GROUP BY severity, signature
        ORDER BY severity ASC, alerts DESC
        LIMIT ?
        """,
        (start_time, end_time, *params, _limit(limit)),
        "ids_summary",
    )


def get_incident_summary(filters, start_time, end_time, limit=DEFAULT_LIMIT):
    where, params = _filter_clause(filters, {"device_ids": "device_ip"})
    return _timed_query(
        f"""
        SELECT id, title, severity, status, device_ip, device_name, first_event_ts, last_event_ts
        FROM security_incidents
        WHERE last_event_ts BETWEEN ? AND ? {where}
        ORDER BY severity ASC, last_event_ts DESC
        LIMIT ?
        """,
        (start_time, end_time, *params, _limit(limit)),
        "incident_summary",
    )


def get_internet_quality_summary(start_time, end_time, limit=DEFAULT_LIMIT):
    return _timed_query(
        """
        SELECT ts, status, diagnosis, internet_latency_ms, internet_loss_pct, jitter_ms, dns_ms,
               public_ip, isp_name, asn, isp_org
        FROM internet_quality
        WHERE ts BETWEEN ? AND ?
        ORDER BY ts DESC
        LIMIT ?
        """,
        (start_time, end_time, _limit(limit)),
        "internet_quality_summary",
    )


def get_internet_issue_summary(start_time, end_time, limit=DEFAULT_LIMIT):
    return _timed_query(
        """
        SELECT ts, status, diagnosis, internet_latency_ms, internet_loss_pct, jitter_ms, dns_ms,
               public_ip, isp_name, asn, isp_org
        FROM internet_quality
        WHERE ts BETWEEN ? AND ?
          AND LOWER(COALESCE(status, '')) NOT IN ('', 'ok', 'healthy')
        ORDER BY ts DESC
        LIMIT ?
        """,
        (start_time, end_time, _limit(limit)),
        "internet_issue_summary",
    )


def get_internet_quality_rollup(start_time, end_time):
    rows = _timed_query(
        """
        SELECT
            COUNT(*) AS samples,
            SUM(CASE WHEN LOWER(COALESCE(status, '')) NOT IN ('', 'ok', 'healthy') THEN 1 ELSE 0 END) AS issue_samples,
            AVG(internet_latency_ms) AS avg_latency_ms,
            MAX(internet_latency_ms) AS worst_latency_ms,
            AVG(internet_loss_pct) AS avg_loss_pct,
            MAX(internet_loss_pct) AS worst_loss_pct,
            AVG(jitter_ms) AS avg_jitter_ms,
            MAX(jitter_ms) AS worst_jitter_ms,
            AVG(dns_ms) AS avg_dns_ms,
            MAX(dns_ms) AS worst_dns_ms,
            COUNT(DISTINCT NULLIF(public_ip, '')) AS public_ip_count,
            COUNT(DISTINCT NULLIF(COALESCE(asn, isp_name, isp_org), '')) AS isp_count,
            MAX(NULLIF(isp_name, '')) AS latest_isp_name,
            MAX(NULLIF(asn, '')) AS latest_asn,
            MAX(NULLIF(public_ip, '')) AS latest_public_ip
        FROM internet_quality
        WHERE ts BETWEEN ? AND ?
        """,
        (start_time, end_time),
        "internet_quality_rollup",
    )
    return rows[0] if rows else {}


def get_speedtest_summary(start_time, end_time, limit=DEFAULT_LIMIT):
    return _timed_query(
        """
        SELECT ts, source, latency_ms, download_mbps, upload_mbps, success
        FROM speed_tests
        WHERE ts BETWEEN ? AND ?
        ORDER BY ts DESC
        LIMIT ?
        """,
        (start_time, end_time, _limit(limit)),
        "speedtest_summary",
    )


def get_configuration_change_summary(start_time, end_time, limit=DEFAULT_LIMIT):
    return _timed_query(
        """
        SELECT ts, component, field, severity, previous_value, new_value, status
        FROM config_change_events
        WHERE ts BETWEEN ? AND ?
        ORDER BY ts DESC
        LIMIT ?
        """,
        (start_time, end_time, _limit(limit)),
        "configuration_change_summary",
    )


def get_activity_timeline(filters, start_time, end_time, limit=DEFAULT_LIMIT):
    device_ids = _clean_list((filters or {}).get("device_ids"))
    device_clause = ""
    device_params = []
    if device_ids:
        placeholders = ",".join(["?"] * len(device_ids))
        device_clause = f"AND client IN ({placeholders})"
        device_params = device_ids
    rows = []
    rows.extend(_timed_query(
        f"""
        SELECT ts, 'DNS' AS category, client AS device, domain AS destination,
               CASE WHEN blocked=1 THEN 'Blocked DNS request' ELSE 'DNS request' END AS description,
               CASE WHEN blocked=1 THEN 'warning' ELSE 'info' END AS severity,
               '/blocked' AS detail_url
        FROM dns_querylog
        WHERE ts BETWEEN ? AND ? {device_clause}
        ORDER BY ts DESC
        LIMIT ?
        """,
        (start_time, end_time, *device_params, _limit(limit // 2)),
        "timeline_dns",
    ))
    rows.extend(_timed_query(
        """
        SELECT ts, 'IDS Alert' AS category, src_ip AS device, dest_ip AS destination,
               signature AS description,
               CASE WHEN severity <= 2 THEN 'high' WHEN severity = 3 THEN 'medium' ELSE 'low' END AS severity,
               '/ids-alerts/' || id AS detail_url
        FROM ids_events
        WHERE event_type='alert' AND ts BETWEEN ? AND ?
        ORDER BY ts DESC
        LIMIT ?
        """,
        (start_time, end_time, _limit(limit // 2)),
        "timeline_ids",
    ))
    return sorted(rows, key=lambda row: str(row["ts"] or ""), reverse=True)[:_limit(limit)]


def get_previous_period_comparison(start_time, end_time):
    start = _parse_dt(start_time)
    end = _parse_dt(end_time)
    if not start or not end:
        return {}
    duration = end - start
    previous_start = _dt_text(start - duration)
    previous_end = _dt_text(start)
    current = get_site_overview(start_time, end_time)
    previous = get_site_overview(previous_start, previous_end)
    return {"current": current, "previous": previous, "previous_start": previous_start, "previous_end": previous_end}


def _scalar(sql, params=()):
    rows = _timed_query(sql, params, "scalar")
    return int(rows[0][0] or 0) if rows else 0


def _timed_query(sql, params=(), label="reporting_query"):
    started = time.perf_counter()
    rows = query(sql, params)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if elapsed_ms >= SLOW_QUERY_MS:
        print(f"Reporting query slow: {label} took {elapsed_ms:.1f} ms")
    return rows


def _clean_list(values):
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    return [str(value).strip() for value in values if str(value or "").strip()]


def _filter_clause(filters, mapping):
    filters = filters or {}
    clauses = []
    params = []
    for key, column in mapping.items():
        values = _clean_list(filters.get(key))
        if values:
            placeholders = ",".join(["?"] * len(values))
            clauses.append(f"AND {column} IN ({placeholders})")
            params.extend(values)
    return " ".join(clauses), params


def _parse_dt(value):
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:len(fmt)], fmt)
        except Exception:
            continue
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _dt_text(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _limit(value):
    try:
        return max(1, min(MAX_LIMIT, int(value)))
    except Exception:
        return DEFAULT_LIMIT
