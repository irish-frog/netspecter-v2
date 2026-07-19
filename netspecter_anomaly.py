import json
import math
import shutil
from datetime import datetime, timedelta

from netspecter_paths import DATA_ROOT


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_ts(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")[:19])
    except Exception:
        pass
    try:
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def day_text(dt):
    return dt.strftime("%Y-%m-%d")


def hour_int(dt):
    return int(dt.strftime("%H"))


def schema_sql():
    return [
        """
        CREATE TABLE IF NOT EXISTS anomaly_device_daily (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            day TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            device_type TEXT,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            dns_queries INTEGER DEFAULT 0,
            blocked_dns INTEGER DEFAULT 0,
            unique_destinations INTEGER DEFAULT 0,
            ids_alerts INTEGER DEFAULT 0,
            countries_json TEXT DEFAULT '[]',
            ports_json TEXT DEFAULT '[]',
            protocols_json TEXT DEFAULT '[]',
            active_hours_json TEXT DEFAULT '[]',
            updated_at TEXT,
            UNIQUE(day, device_ip)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS anomaly_device_hourly (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            day TEXT NOT NULL,
            hour INTEGER NOT NULL,
            device_ip TEXT NOT NULL,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            dns_queries INTEGER DEFAULT 0,
            unique_destinations INTEGER DEFAULT 0,
            updated_at TEXT,
            UNIQUE(day, hour, device_ip)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS anomaly_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            ts TEXT NOT NULL,
            day TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            device_type TEXT,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER DEFAULT 0,
            status TEXT DEFAULT 'new',
            current_value TEXT,
            normal_value TEXT,
            baseline_period TEXT,
            threshold TEXT,
            reason TEXT,
            maturity_days INTEGER DEFAULT 0,
            learning_only INTEGER DEFAULT 1,
            expected INTEGER DEFAULT 0,
            learned_at TEXT,
            suppressed_until TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS anomaly_expected_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            actor TEXT,
            note TEXT,
            learn_from_event INTEGER DEFAULT 0
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_anomaly_daily_device_day ON anomaly_device_daily(device_ip, day)",
        "CREATE INDEX IF NOT EXISTS idx_anomaly_hourly_device_day ON anomaly_device_hourly(device_ip, day, hour)",
        "CREATE INDEX IF NOT EXISTS idx_anomaly_events_day ON anomaly_events(day)",
        "CREATE INDEX IF NOT EXISTS idx_anomaly_events_status ON anomaly_events(status)",
        "CREATE INDEX IF NOT EXISTS idx_anomaly_events_device ON anomaly_events(device_ip)",
    ]


def ensure_schema(con):
    for sql in schema_sql():
        con.execute(sql)


def safe_json_list(value):
    try:
        data = json.loads(value or "[]")
        if isinstance(data, list):
            return [str(item) for item in data]
    except Exception:
        pass
    return []


def percentile(values, pct):
    nums = sorted(float(v or 0) for v in values)
    if not nums:
        return 0.0
    if len(nums) == 1:
        return nums[0]
    pos = (len(nums) - 1) * pct
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return nums[int(pos)]
    return nums[low] + (nums[high] - nums[low]) * (pos - low)


def device_excluded(config, device_ip):
    return str(device_ip or "") in {str(ip).strip() for ip in config.get("anomaly_excluded_devices", [])}


def thresholds_for(config, device_type):
    defaults = {
        "upload_min_mb": float(config.get("anomaly_upload_min_mb", 250) or 250),
        "upload_multiplier": float(config.get("anomaly_upload_multiplier", 4) or 4),
        "dest_multiplier": float(config.get("anomaly_destination_multiplier", 3) or 3),
        "dns_multiplier": float(config.get("anomaly_dns_multiplier", 4) or 4),
        "new_ip_min": int(config.get("anomaly_new_ip_min", 25) or 25),
    }
    type_map = config.get("anomaly_device_type_thresholds") or {}
    override = type_map.get(str(device_type or "Unknown")) if isinstance(type_map, dict) else None
    if isinstance(override, dict):
        for key, value in override.items():
            if key in defaults:
                defaults[key] = float(value)
    return defaults


def aggregate_day(con, day):
    ensure_schema(con)
    rows = con.execute(
        """
        SELECT t.ip, COALESCE(o.device_type, d.device_type, 'Unknown') AS device_type,
               COALESCE(SUM(t.downloaded_mb), 0), COALESCE(SUM(t.uploaded_mb), 0)
        FROM traffic_intervals t
        LEFT JOIN devices d ON d.ip=t.ip
        LEFT JOIN device_overrides o ON o.ip=t.ip
        WHERE t.day=?
        GROUP BY t.ip
        """,
        (day,),
    ).fetchall()
    ips = {row[0] for row in rows}
    for ip, device_type, down, up in rows:
        dns = con.execute("SELECT COUNT(*), COALESCE(SUM(blocked), 0) FROM dns_querylog WHERE day=? AND client=?", (day, ip)).fetchone()
        remote = con.execute("SELECT COUNT(DISTINCT remote_ip) FROM remote_traffic_intervals WHERE day=? AND ip=?", (day, ip)).fetchone()
        ids = con.execute("SELECT COUNT(*) FROM ids_events WHERE day=? AND src_ip=? AND event_type='alert'", (day, ip)).fetchone()
        countries = [r[0] for r in con.execute(
            """
            SELECT DISTINCT COALESCE(l.country_code, l.country, '')
            FROM remote_traffic_intervals r
            LEFT JOIN remote_ip_locations l ON l.remote_ip=r.remote_ip
            WHERE r.day=? AND r.ip=? AND COALESCE(l.country_code, l.country, '')<>''
            """,
            (day, ip),
        ).fetchall()]
        ports = [str(r[0]) for r in con.execute("SELECT DISTINCT dest_port FROM ids_events WHERE day=? AND src_ip=? AND dest_port IS NOT NULL", (day, ip)).fetchall()]
        protocols = [str(r[0]) for r in con.execute("SELECT DISTINCT COALESCE(app_proto, protocol, '') FROM ids_events WHERE day=? AND src_ip=? AND COALESCE(app_proto, protocol, '')<>''", (day, ip)).fetchall()]
        active_hours = sorted({hour_int(parse_ts(r[0])) for r in con.execute("SELECT ts FROM traffic_intervals WHERE day=? AND ip=? AND total_mb>0", (day, ip)).fetchall() if parse_ts(r[0]) is not None})
        con.execute(
            """
            INSERT INTO anomaly_device_daily
                (day, device_ip, device_type, downloaded_mb, uploaded_mb, dns_queries, blocked_dns,
                 unique_destinations, ids_alerts, countries_json, ports_json, protocols_json, active_hours_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(day, device_ip) DO UPDATE SET
                device_type=excluded.device_type,
                downloaded_mb=excluded.downloaded_mb,
                uploaded_mb=excluded.uploaded_mb,
                dns_queries=excluded.dns_queries,
                blocked_dns=excluded.blocked_dns,
                unique_destinations=excluded.unique_destinations,
                ids_alerts=excluded.ids_alerts,
                countries_json=excluded.countries_json,
                ports_json=excluded.ports_json,
                protocols_json=excluded.protocols_json,
                active_hours_json=excluded.active_hours_json,
                updated_at=excluded.updated_at
            """,
            (day, ip, device_type, down, up, int(dns[0] or 0), int(dns[1] or 0), int(remote[0] or 0), int(ids[0] or 0),
             json.dumps(sorted(countries)), json.dumps(sorted(ports)), json.dumps(sorted(protocols)), json.dumps(active_hours), now_text()),
        )
    hourly = con.execute(
        """
        SELECT day, CAST(strftime('%H', ts) AS INTEGER) AS hour, ip,
               COALESCE(SUM(downloaded_mb), 0), COALESCE(SUM(uploaded_mb), 0)
        FROM traffic_intervals
        WHERE day=?
        GROUP BY day, hour, ip
        """,
        (day,),
    ).fetchall()
    for day_value, hour, ip, down, up in hourly:
        ips.add(ip)
        dns_count = con.execute("SELECT COUNT(*) FROM dns_querylog WHERE day=? AND client=? AND CAST(strftime('%H', ts) AS INTEGER)=?", (day_value, ip, hour)).fetchone()[0]
        dests = con.execute("SELECT COUNT(DISTINCT remote_ip) FROM remote_traffic_intervals WHERE day=? AND ip=? AND CAST(strftime('%H', ts) AS INTEGER)=?", (day_value, ip, hour)).fetchone()[0]
        con.execute(
            """
            INSERT INTO anomaly_device_hourly
                (day, hour, device_ip, downloaded_mb, uploaded_mb, dns_queries, unique_destinations, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(day, hour, device_ip) DO UPDATE SET
                downloaded_mb=excluded.downloaded_mb,
                uploaded_mb=excluded.uploaded_mb,
                dns_queries=excluded.dns_queries,
                unique_destinations=excluded.unique_destinations,
                updated_at=excluded.updated_at
            """,
            (day_value, hour, ip, down, up, int(dns_count or 0), int(dests or 0), now_text()),
        )
    return len(ips)


def maturity(con, device_ip, before_day, recommended_days):
    rows = con.execute(
        "SELECT day FROM anomaly_device_daily WHERE device_ip=? AND day<? ORDER BY day DESC LIMIT ?",
        (device_ip, before_day, int(recommended_days)),
    ).fetchall()
    return len({row[0] for row in rows})


def baseline_stats(con, device_ip, before_day, recommended_days):
    rows = con.execute(
        """
        SELECT uploaded_mb, downloaded_mb, dns_queries, blocked_dns, unique_destinations,
               ids_alerts, countries_json, ports_json, protocols_json, active_hours_json
        FROM anomaly_device_daily
        WHERE device_ip=? AND day<?
        ORDER BY day DESC LIMIT ?
        """,
        (device_ip, before_day, int(recommended_days)),
    ).fetchall()
    stats = {
        "days": len(rows),
        "upload_p95": percentile([r[0] for r in rows], 0.95),
        "dest_p95": percentile([r[4] for r in rows], 0.95),
        "dns_p95": percentile([r[2] for r in rows], 0.95),
        "countries": set(),
        "ports": set(),
        "protocols": set(),
        "hours": set(),
    }
    for row in rows:
        stats["countries"].update(safe_json_list(row[6]))
        stats["ports"].update(safe_json_list(row[7]))
        stats["protocols"].update(safe_json_list(row[8]))
        stats["hours"].update(int(h) for h in safe_json_list(row[9]) if str(h).isdigit())
    return stats


def event_key(device_ip, day, rule, detail):
    return "|".join([str(device_ip), str(day), str(rule), str(detail)])[:300]


def add_anomaly(con, device_ip, device_type, day, rule, severity, confidence, current, normal, threshold, reason, maturity_days, learning_only, detail):
    key = event_key(device_ip, day, rule, detail)
    con.execute(
        """
        INSERT OR IGNORE INTO anomaly_events
            (event_key, ts, day, device_ip, device_type, rule, severity, confidence, current_value,
             normal_value, baseline_period, threshold, reason, maturity_days, learning_only, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            key, now_text(), day, device_ip, device_type, rule, severity, int(confidence),
            str(current)[:200], str(normal)[:200], f"{maturity_days} usable day(s)", str(threshold)[:200],
            reason[:600], int(maturity_days), 1 if learning_only else 0, now_text(), now_text(),
        ),
    )
    return con.total_changes


def detect_for_day(con, day, config):
    ensure_schema(con)
    min_days = int(config.get("anomaly_min_learning_days", 7) or 7)
    recommended = int(config.get("anomaly_recommended_learning_days", 14) or 14)
    learning_only_config = bool(config.get("anomaly_learning_only", True))
    created_before = con.total_changes
    rows = con.execute(
        """
        SELECT device_ip, device_type, uploaded_mb, dns_queries, unique_destinations,
               countries_json, ports_json, protocols_json, active_hours_json
        FROM anomaly_device_daily
        WHERE day=?
        """,
        (day,),
    ).fetchall()
    for row in rows:
        device_ip, device_type, uploaded, dns_queries, dest_count, countries_json, ports_json, protocols_json, hours_json = row
        if device_excluded(config, device_ip):
            continue
        stats = baseline_stats(con, device_ip, day, recommended)
        mature = stats["days"] >= min_days
        learning_only = learning_only_config or not mature
        thresholds = thresholds_for(config, device_type)
        current_countries = set(safe_json_list(countries_json))
        current_ports = set(safe_json_list(ports_json))
        current_protocols = set(safe_json_list(protocols_json))
        current_hours = {int(h) for h in safe_json_list(hours_json) if str(h).isdigit()}
        upload_threshold = max(thresholds["upload_min_mb"], stats["upload_p95"] * thresholds["upload_multiplier"])
        if uploaded >= upload_threshold and (mature or uploaded >= thresholds["upload_min_mb"] * 10):
            add_anomaly(con, device_ip, device_type, day, "large_upload", "high", 80 if mature else 45, f"{uploaded:.2f} MB", f"p95 {stats['upload_p95']:.2f} MB", f">= {upload_threshold:.2f} MB", "Upload exceeds fixed minimum and baseline multiplier.", stats["days"], learning_only, "upload")
        dest_threshold = max(thresholds["new_ip_min"], stats["dest_p95"] * thresholds["dest_multiplier"])
        if dest_count >= dest_threshold and (mature or dest_count >= thresholds["new_ip_min"] * 3):
            add_anomaly(con, device_ip, device_type, day, "destination_spike", "medium", 75 if mature else 40, int(dest_count), f"p95 {stats['dest_p95']:.1f}", f">= {dest_threshold:.1f}", "Unique external destination count spiked.", stats["days"], learning_only, "dests")
        dns_threshold = max(100, stats["dns_p95"] * thresholds["dns_multiplier"])
        if dns_queries >= dns_threshold and (mature or dns_queries >= 1000):
            add_anomaly(con, device_ip, device_type, day, "dns_spike", "medium", 70 if mature else 40, int(dns_queries), f"p95 {stats['dns_p95']:.1f}", f">= {dns_threshold:.1f}", "DNS query count exceeds baseline multiplier.", stats["days"], learning_only, "dns")
        for country in sorted(current_countries - stats["countries"]):
            if country and mature:
                add_anomaly(con, device_ip, device_type, day, "new_country", "medium", 70, country, ", ".join(sorted(stats["countries"])) or "none", "country not previously seen", "First connection to a new destination country.", stats["days"], learning_only, country)
        for port in sorted(current_ports - stats["ports"]):
            if port and mature:
                add_anomaly(con, device_ip, device_type, day, "new_port", "medium", 65, port, ", ".join(sorted(stats["ports"])) or "none", "port not in baseline", "Unusual outbound destination port.", stats["days"], learning_only, port)
        for proto in sorted(current_protocols - stats["protocols"]):
            if proto and mature:
                add_anomaly(con, device_ip, device_type, day, "new_protocol", "medium", 65, proto, ", ".join(sorted(stats["protocols"])) or "none", "protocol not in baseline", "Unusual application protocol.", stats["days"], learning_only, proto)
        for hour in sorted(current_hours - stats["hours"]):
            if mature:
                add_anomaly(con, device_ip, device_type, day, "unusual_active_hour", "low", 55, f"{hour:02d}:00", ", ".join(f"{h:02d}:00" for h in sorted(stats["hours"])) or "none", "hour not in baseline", "Activity outside normal active hours.", stats["days"], learning_only, hour)
        dtype = str(device_type or "").lower()
        if any(token in dtype for token in ("printer", "camera")) and (uploaded > 100 or dest_count > 20):
            add_anomaly(con, device_ip, device_type, day, "iot_workstation_behavior", "medium", 60 if mature else 35, f"{uploaded:.1f} MB, {dest_count} destinations", "printer/camera low outbound profile", "upload >100 MB or >20 destinations", "Printer/camera behaving like a workstation.", stats["days"], learning_only, "iot")
        if "server" in dtype and (current_ports - stats["ports"]) and mature:
            add_anomaly(con, device_ip, device_type, day, "server_unusual_outbound", "medium", 65, ", ".join(sorted(current_ports - stats["ports"])), ", ".join(sorted(stats["ports"])) or "none", "new outbound port", "Server initiated unusual outbound traffic.", stats["days"], learning_only, "server")
    return con.total_changes - created_before


def run_anomaly_cycle(connect_db, config, target_day=None):
    day = target_day or day_text(datetime.now())
    con = connect_db()
    ensure_schema(con)
    aggregate_day(con, day)
    count = detect_for_day(con, day, config)
    con.commit()
    con.close()
    return count


def mark_expected(connect_db, event_id, actor="analyst", note="", learn=False):
    con = connect_db()
    ensure_schema(con)
    row = con.execute("SELECT device_ip, day FROM anomaly_events WHERE id=?", (int(event_id),)).fetchone()
    if not row:
        con.close()
        return False
    con.execute("UPDATE anomaly_events SET status='expected', expected=1, learned_at=CASE WHEN ? THEN ? ELSE learned_at END, updated_at=? WHERE id=?", (1 if learn else 0, now_text(), now_text(), int(event_id)))
    con.execute("INSERT INTO anomaly_expected_events (event_id, ts, actor, note, learn_from_event) VALUES (?, ?, ?, ?, ?)", (int(event_id), now_text(), actor[:80], note[:1000], 1 if learn else 0))
    con.commit()
    con.close()
    return True


def list_anomalies(connect_db, limit=200):
    con = connect_db()
    con.row_factory = None
    ensure_schema(con)
    rows = con.execute(
        """
        SELECT id, ts, device_ip, device_type, rule, severity, confidence, status, current_value,
               normal_value, threshold, reason, maturity_days, learning_only
        FROM anomaly_events
        ORDER BY id DESC LIMIT ?
        """,
        (int(limit),),
    ).fetchall()
    con.close()
    return rows


def anomaly_detail(connect_db, event_id):
    con = connect_db()
    con.row_factory = None
    ensure_schema(con)
    event = con.execute("SELECT * FROM anomaly_events WHERE id=?", (int(event_id),)).fetchone()
    expected = con.execute("SELECT ts, actor, note, learn_from_event FROM anomaly_expected_events WHERE event_id=? ORDER BY id DESC", (int(event_id),)).fetchall()
    con.close()
    return event, expected


def baseline_summary(connect_db):
    con = connect_db()
    ensure_schema(con)
    row = con.execute("SELECT COUNT(DISTINCT day), COUNT(DISTINCT device_ip) FROM anomaly_device_daily").fetchone()
    latest = con.execute("SELECT MAX(day) FROM anomaly_device_daily").fetchone()[0]
    open_count = con.execute("SELECT COUNT(*) FROM anomaly_events WHERE status='new'").fetchone()[0]
    con.close()
    return {"days": int(row[0] or 0), "devices": int(row[1] or 0), "latest": latest or "-", "open": int(open_count or 0)}


def prune_anomalies(connect_db, config):
    days = int(config.get("anomaly_retention_days", 180) or 180)
    max_events = int(config.get("anomaly_max_events", 100000) or 100000)
    min_free_mb = int(config.get("anomaly_min_free_mb", 512) or 512)
    cutoff = day_text(datetime.now() - timedelta(days=days))
    con = connect_db()
    ensure_schema(con)
    con.execute("DELETE FROM anomaly_device_hourly WHERE day<?", (cutoff,))
    con.execute("DELETE FROM anomaly_device_daily WHERE day<?", (cutoff,))
    con.execute("DELETE FROM anomaly_events WHERE day<? AND status!='expected'", (cutoff,))
    count = con.execute("SELECT COUNT(*) FROM anomaly_events").fetchone()[0]
    if count > max_events:
        con.execute("DELETE FROM anomaly_events WHERE id IN (SELECT id FROM anomaly_events WHERE status!='expected' ORDER BY id ASC LIMIT ?)", (count - max_events,))
    try:
        free_mb = shutil.disk_usage(str(DATA_ROOT)).free / 1024 / 1024
    except Exception:
        free_mb = min_free_mb + 1
    if free_mb < min_free_mb:
        con.execute("DELETE FROM anomaly_events WHERE id IN (SELECT id FROM anomaly_events WHERE status!='expected' ORDER BY id ASC LIMIT 1000)")
    existing = {row[0] for row in con.execute("SELECT id FROM anomaly_events").fetchall()}
    if existing:
        placeholders = ",".join("?" for _ in existing)
        con.execute(f"DELETE FROM anomaly_expected_events WHERE event_id NOT IN ({placeholders})", tuple(existing))
    else:
        con.execute("DELETE FROM anomaly_expected_events")
    con.commit()
    con.close()
