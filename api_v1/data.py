from datetime import datetime, timedelta

from netspecter_db import query
from netspecter_incidents import severity_label
from netspecter_internet_quality import latest_quality
from netspecter_ids import recent_structured_alerts
from netspecter_threat_intel import feed_states
from services.report_context_service import build_reporting_context_from_request
from services.reporting_service import (
    get_activity_timeline,
    get_application_summary,
    get_configuration_change_summary,
    get_dns_summary,
    get_internet_issue_summary,
    get_internet_quality_rollup,
    get_site_overview,
    get_speedtest_summary,
)


def row_dict(row):
    return {key: row[key] for key in row.keys()}


def rows_dict(rows):
    return [row_dict(row) for row in rows or []]


def period(days=7):
    end = datetime.now()
    start = end - timedelta(days=int(days or 7))
    return start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")


def dashboard_summary():
    start, end = period(7)
    overview = get_site_overview(start, end)
    latest = latest_quality(_connect_proxy) or {}
    recent_items = incidents(limit=5)
    return {
        "device_count": overview.get("devices", 0),
        "internet_status": latest.get("status") or "unknown",
        "active_alerts": overview.get("ids_alerts", 0),
        "threat_count": threat_count(),
        "dns_health": {
            "query_volume_7d": overview.get("dns_total", 0),
            "blocked_7d": overview.get("dns_blocked", 0),
            "latest_dns_response_ms": latest.get("dns_ms"),
        },
        "recent_incidents": recent_items["items"],
        "period": {"start": start, "end": end},
    }


def devices(limit=500):
    rows = query(
        """
        SELECT d.ip, COALESCE(o.name, d.name, d.ip) AS hostname, d.mac, d.vendor,
               d.status, d.last_seen, COALESCE(SUM(t.downloaded_mb), 0) AS downloaded_mb,
               COALESCE(SUM(t.uploaded_mb), 0) AS uploaded_mb,
               COALESCE(SUM(t.total_mb), 0) AS total_mb
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        LEFT JOIN traffic_intervals t ON t.ip=d.ip AND t.ts >= datetime('now', '-7 days')
        WHERE COALESCE(d.ignored, 0)=0
        GROUP BY d.ip
        ORDER BY d.last_seen DESC
        LIMIT ?
        """,
        (int(limit),),
    )
    return {"items": [_device_payload(row) for row in rows]}


def device(device_id):
    rows = query(
        """
        SELECT d.ip, COALESCE(o.name, d.name, d.ip) AS hostname, d.mac, d.vendor,
               d.status, d.last_seen, COALESCE(SUM(t.downloaded_mb), 0) AS downloaded_mb,
               COALESCE(SUM(t.uploaded_mb), 0) AS uploaded_mb,
               COALESCE(SUM(t.total_mb), 0) AS total_mb
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        LEFT JOIN traffic_intervals t ON t.ip=d.ip AND t.ts >= datetime('now', '-7 days')
        WHERE d.ip=? OR d.mac=?
        GROUP BY d.ip
        LIMIT 1
        """,
        (device_id, device_id),
    )
    return _device_payload(rows[0]) if rows else None


def _device_payload(row):
    return {
        "id": row["ip"],
        "hostname": row["hostname"],
        "ip": row["ip"],
        "mac": row["mac"],
        "vendor": row["vendor"],
        "status": row["status"],
        "last_seen": row["last_seen"],
        "traffic_statistics": {
            "period": "last_7_days",
            "downloaded_mb": row["downloaded_mb"],
            "uploaded_mb": row["uploaded_mb"],
            "total_mb": row["total_mb"],
        },
    }


def internet_health():
    start, end = period(7)
    latest = latest_quality(_connect_proxy) or {}
    rollup = get_internet_quality_rollup(start, end)
    outage_rows = get_internet_issue_summary(start, end, 1)
    return {
        "availability": _availability(rollup),
        "latency_ms": latest.get("internet_latency_ms"),
        "jitter_ms": latest.get("jitter_ms"),
        "packet_loss_pct": latest.get("internet_loss_pct"),
        "dns_response_time_ms": latest.get("dns_ms"),
        "last_outage": row_dict(outage_rows[0]) if outage_rows else None,
        "period_rollup": row_dict(rollup) if hasattr(rollup, "keys") else rollup,
    }


def dns_analytics():
    start, end = period(7)
    top_domains = get_dns_summary({}, start, end, 10)
    top_clients = query(
        """
        SELECT client, COUNT(*) AS queries, SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END) AS blocked
        FROM dns_querylog
        WHERE ts BETWEEN ? AND ?
        GROUP BY client
        ORDER BY queries DESC
        LIMIT 10
        """,
        (start, end),
    )
    blocked = query(
        """
        SELECT domain, COUNT(*) AS blocked_queries
        FROM dns_querylog
        WHERE blocked=1 AND ts BETWEEN ? AND ?
        GROUP BY domain
        ORDER BY blocked_queries DESC
        LIMIT 10
        """,
        (start, end),
    )
    latest = latest_quality(_connect_proxy) or {}
    return {
        "top_domains": rows_dict(top_domains),
        "top_clients": rows_dict(top_clients),
        "blocked_domains": rows_dict(blocked),
        "query_volume": sum(int(row["queries"] or 0) for row in top_clients),
        "dns_latency_ms": latest.get("dns_ms"),
        "period": {"start": start, "end": end},
    }


def alerts(limit=100):
    items = []
    for alert in recent_structured_alerts(_connect_proxy, limit=limit):
        items.append({
            "id": alert.get("id"),
            "severity": alert.get("severity_label") or severity_label(alert.get("severity")),
            "source_ip": alert.get("src_ip") or alert.get("source_ip"),
            "destination_ip": alert.get("dest_ip") or alert.get("destination_ip"),
            "signature": alert.get("signature"),
            "timestamp": alert.get("ts"),
            "status": alert.get("status") or "new",
        })
    return {"items": items}


def threats():
    rows = query(
        """
        SELECT c.id, c.ts, c.indicator_value, c.indicator_type, c.source_table,
               c.source_id, c.remote_ip, c.device_ip, c.risk_score, i.source AS feed_name
        FROM threat_correlations c
        LEFT JOIN threat_indicators i ON i.id=c.indicator_id
        ORDER BY c.ts DESC
        LIMIT 100
        """
    )
    return {
        "threat_matches": rows_dict(rows),
        "risk_scores": risk_scores(),
        "known_malicious_hosts": known_malicious_hosts(),
        "historical_detections": len(rows),
        "feeds": feed_states(_connect_proxy),
    }


def incidents(limit=100):
    rows = query(
        """
        SELECT id, severity, device_ip, device_name, first_event_ts, last_event_ts,
               status, title, summary
        FROM security_incidents
        ORDER BY last_event_ts DESC
        LIMIT ?
        """,
        (int(limit),),
    )
    return {"items": [{**row_dict(row), "severity_label": severity_label(row["severity"])} for row in rows]}


def incident_timeline(limit=100):
    start, end = period(30)
    timeline = rows_dict(get_activity_timeline({}, start, end, limit))
    changes = rows_dict(get_configuration_change_summary(start, end, 25))
    outages = rows_dict(get_internet_issue_summary(start, end, 25))
    return {"items": sorted(timeline + _tag(changes, "Config Change") + _tag(outages, "Internet Outage"), key=lambda item: str(item.get("ts", "")), reverse=True)[:limit]}


def report(period_name):
    days = {"daily": 1, "weekly": 7, "monthly": 30}.get(period_name, 7)
    start, end = period(days)
    return {
        "report_type": period_name,
        "period": {"start": start, "end": end},
        "overview": get_site_overview(start, end),
        "dns": rows_dict(get_dns_summary({}, start, end, 10)),
        "applications": rows_dict(get_application_summary({}, start, end, 10)),
        "internet_quality": rows_dict(get_speedtest_summary(start, end, 10)),
        "incidents": incidents(20)["items"],
    }


def ai_summary(kind):
    args = _Args({"period": "7d" if kind != "executive-summary" else "30d"})
    context = build_reporting_context_from_request(args)
    return {
        "summary_type": kind,
        "period": {"start": context["start_time"], "end": context["end_time"]},
        "overview": context["overview"],
        "findings": context["findings"],
        "top_devices": rows_dict(context["top_devices"]),
        "top_applications": rows_dict(context["app_rows"]),
        "top_dns": rows_dict(context["dns_rows"]),
        "internet_quality": {
            "rollup": row_dict(context["internet_quality_rollup"]) if hasattr(context["internet_quality_rollup"], "keys") else context["internet_quality_rollup"],
            "issues": rows_dict(context["internet_issue_rows"][:10]),
        },
        "security": {
            "alerts": alerts(20)["items"],
            "incidents": incidents(20)["items"],
            "threats": threats()["risk_scores"],
        },
        "ai_notes": [
            "This endpoint is condensed for report generation.",
            "Use raw endpoints only when the AI agent needs drill-down evidence.",
        ],
    }


def openapi_spec():
    paths = {}
    for path in [
        "/api/v1/dashboard", "/api/v1/devices", "/api/v1/devices/{id}", "/api/v1/internet",
        "/api/v1/dns", "/api/v1/alerts", "/api/v1/threats", "/api/v1/incidents",
        "/api/v1/reports/daily", "/api/v1/reports/weekly", "/api/v1/reports/monthly",
        "/api/v1/ai/network-summary", "/api/v1/ai/executive-summary", "/api/v1/ai/security-summary",
    ]:
        paths[path] = {"get": {"security": [{"ApiKeyAuth": []}], "responses": {"200": {"description": "OK"}}}}
    return {
        "openapi": "3.0.3",
        "info": {"title": "NetSpecter AI Integration API", "version": "1.0.0"},
        "servers": [{"url": "/api/v1"}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                "BearerAuth": {"type": "http", "scheme": "bearer"},
            }
        },
    }


def _availability(rollup):
    try:
        samples = int(rollup["samples"] or 0)
        issue_samples = int(rollup["issue_samples"] or 0)
        return round(max(0, (samples - issue_samples) / samples) * 100, 2) if samples else None
    except Exception:
        return None


def risk_scores():
    rows = query("SELECT risk_score, COUNT(*) AS matches FROM threat_correlations GROUP BY risk_score ORDER BY risk_score DESC")
    return rows_dict(rows)


def known_malicious_hosts():
    rows = query("SELECT indicator_value, indicator_type, source, risk_score FROM threat_indicators ORDER BY risk_score DESC LIMIT 50")
    return rows_dict(rows)


def threat_count():
    rows = query("SELECT COUNT(*) AS total FROM threat_correlations WHERE ts >= datetime('now', '-7 days')")
    return int(rows[0]["total"] or 0) if rows else 0


def _tag(items, category):
    for item in items:
        item.setdefault("category", category)
        item.setdefault("description", item.get("diagnosis") or item.get("field") or category)
    return items


def _connect_proxy():
    from netspecter_db import connect_db
    return connect_db()


class _Args:
    def __init__(self, values):
        self.values = values

    def get(self, key, default=None):
        return self.values.get(key, default)

    def getlist(self, key):
        value = self.values.get(key, [])
        return value if isinstance(value, list) else [value]
