import json
import re
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
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        if len(text) > 5 and (text[-5] in "+-") and text[-3] != ":":
            text = text[:-2] + ":" + text[-2:]
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except Exception:
            continue
    return None


def dt_text(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def incident_schema_sql():
    return [
        """
        CREATE TABLE IF NOT EXISTS security_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_key TEXT NOT NULL UNIQUE,
            severity INTEGER NOT NULL,
            device_ip TEXT,
            device_mac TEXT,
            device_name TEXT,
            first_event_ts TEXT NOT NULL,
            last_event_ts TEXT NOT NULL,
            status TEXT DEFAULT 'new',
            assigned_to TEXT,
            title TEXT,
            summary TEXT,
            anchor_event_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            closed_at TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS security_incident_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            source_table TEXT NOT NULL,
            source_id TEXT NOT NULL,
            event_ts TEXT,
            event_type TEXT NOT NULL,
            summary TEXT,
            reason TEXT,
            UNIQUE(incident_id, source_table, source_id, event_type)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS security_incident_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            author TEXT,
            note TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS security_incident_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT,
            detail TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_severity ON security_incidents(severity)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_first ON security_incidents(first_event_ts)",
        "CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON security_incident_events(incident_id)",
        "CREATE INDEX IF NOT EXISTS idx_incident_events_source ON security_incident_events(source_table, source_id)",
        "CREATE INDEX IF NOT EXISTS idx_incident_audit_incident ON security_incident_audit(incident_id)",
    ]


def ensure_schema(con):
    for sql in incident_schema_sql():
        con.execute(sql)


def severity_label(value):
    try:
        sev = int(value or 3)
    except Exception:
        sev = 3
    return "Critical" if sev == 1 else "High" if sev == 2 else "Medium" if sev == 3 else "Low"


def normalize_incident_signature(value):
    return re.sub(r"\s+", " ", str(value or "Suricata alert").strip()).lower()


def normalize_incident_ip(value):
    return str(value or "").strip().lower()


def stable_incident_key(signature, source_ip):
    return f"ids|{normalize_incident_signature(signature)}|{normalize_incident_ip(source_ip)}"


def incident_key_for(row, bucket_minutes=60):
    return stable_incident_key(row["signature"] or row["signature_id"] or "alert", row["src_ip"] or "")


def add_incident_event(con, incident_id, source_table, source_id, event_ts, event_type, summary, reason):
    con.execute(
        """
        INSERT OR IGNORE INTO security_incident_events
            (incident_id, source_table, source_id, event_ts, event_type, summary, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            str(source_table)[:80],
            str(source_id)[:120],
            str(event_ts or "")[:40],
            str(event_type)[:80],
            str(summary or "")[:500],
            str(reason or "")[:500],
        ),
    )


def audit(con, incident_id, action, detail="", actor="system"):
    con.execute(
        "INSERT INTO security_incident_audit (incident_id, ts, action, actor, detail) VALUES (?, ?, ?, ?, ?)",
        (incident_id, now_text(), str(action)[:80], str(actor or "")[:80], str(detail or "")[:500]),
    )


def device_info(con, ip):
    if not ip:
        return {"mac": "", "name": ""}
    try:
        row = con.execute("SELECT mac, name FROM devices WHERE ip=?", (ip,)).fetchone()
        if row:
            return {"mac": row[0] or "", "name": row[1] or ""}
    except Exception:
        pass
    return {"mac": "", "name": ""}


def existing_daily_incidents(con, device_ip, since):
    return con.execute(
        "SELECT COUNT(*) FROM security_incidents WHERE device_ip=? AND created_at>=?",
        (device_ip or "", dt_text(since)),
    ).fetchone()[0]


def find_or_create_incident(con, alert, config):
    bucket_minutes = int(config.get("incident_dedupe_minutes", 60) or 60)
    key = incident_key_for(alert, bucket_minutes)
    row = con.execute("SELECT id FROM security_incidents WHERE incident_key=?", (key,)).fetchone()
    if row:
        return row[0], False
    ts = str(alert["ts"])
    event_dt = parse_ts(ts) or datetime.now()
    max_daily = int(config.get("incident_max_per_device_per_day", 20) or 20)
    if max_daily > 0 and existing_daily_incidents(con, alert["src_ip"], event_dt - timedelta(hours=24)) >= max_daily:
        return None, False
    info = device_info(con, alert["src_ip"])
    sev = int(alert["severity"] or 3)
    title = f"P{sev} IDS: {alert['signature'] or 'Suricata alert'}"
    summary = f"{alert['src_ip'] or 'unknown source'} -> {alert['dest_ip'] or 'unknown destination'}"
    cur = con.execute(
        """
        INSERT INTO security_incidents
            (incident_key, severity, device_ip, device_mac, device_name, first_event_ts, last_event_ts,
             status, title, summary, anchor_event_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?)
        """,
        (key, sev, alert["src_ip"], info["mac"], info["name"], ts, ts, title[:300], summary[:500], alert["id"], now_text(), now_text()),
    )
    incident_id = cur.lastrowid
    audit(con, incident_id, "created", "Created from configured P1/P2 Suricata alert.")
    return incident_id, True


def correlate_alert(con, incident_id, alert, config):
    window = int(config.get("incident_window_minutes", 15) or 15)
    event_dt = parse_ts(alert["ts"]) or datetime.now()
    start = dt_text(event_dt - timedelta(minutes=window))
    end = dt_text(event_dt + timedelta(minutes=window))
    device = alert["src_ip"] or ""
    dest = alert["dest_ip"] or ""
    flow = str(alert["flow_id"] or "")
    signature = alert["signature"] or "Suricata alert"

    add_incident_event(
        con,
        incident_id,
        "ids_events",
        alert["id"],
        alert["ts"],
        "suricata_alert",
        f"P{alert['severity'] or 3} {signature}",
        "Anchor event: configured P1/P2 Suricata alert met incident criteria.",
    )
    if flow:
        rows = con.execute(
            """
            SELECT id, ts, event_type, COALESCE(signature, query, hostname, tls_sni, filename, anomaly_event, event_type)
            FROM ids_events
            WHERE id<>? AND flow_id=? AND ts BETWEEN ? AND ?
            ORDER BY ts ASC LIMIT 100
            """,
            (alert["id"], flow, start, end),
        ).fetchall()
        for row in rows:
            add_incident_event(con, incident_id, "ids_events", row[0], row[1], row[2], row[3], "Same Suricata flow ID inside the investigation window.")
    rows = con.execute(
        """
        SELECT id, ts, event_type, COALESCE(signature, query, hostname, tls_sni, filename, anomaly_event, event_type)
        FROM ids_events
        WHERE id<>? AND ts BETWEEN ? AND ?
          AND ((src_ip=? AND ?<>'') OR (dest_ip=? AND ?<>'') OR (dest_ip=? AND ?<>''))
        ORDER BY ts ASC LIMIT 100
        """,
        (alert["id"], start, end, device, device, device, device, dest, dest),
    ).fetchall()
    for row in rows:
        add_incident_event(con, incident_id, "ids_events", row[0], row[1], row[2], row[3], "Matched device or destination inside the investigation window.")
    rows = con.execute(
        """
        SELECT id, ts, domain, blocked, category
        FROM dns_querylog
        WHERE ts BETWEEN ? AND ? AND (client=? OR domain IN (
            SELECT domain FROM threat_correlations WHERE (dest_ip=? OR device_ip=?) AND domain IS NOT NULL
        ))
        ORDER BY ts ASC LIMIT 100
        """,
        (start, end, device, dest, device),
    ).fetchall()
    for row in rows:
        decision = "blocked" if int(row[3] or 0) else "allowed"
        add_incident_event(con, incident_id, "dns_querylog", row[0], row[1], "dns_query", row[2], f"DNS query by related device; AdGuard decision: {decision}.")
    rows = con.execute(
        """
        SELECT id, ts, reputation, indicator, source, reason, dest_ip, domain
        FROM threat_correlations
        WHERE ts BETWEEN ? AND ? AND ((device_ip=? AND ?<>'') OR (dest_ip=? AND ?<>'') OR (domain IN (
            SELECT domain FROM dns_querylog WHERE client=? AND ts BETWEEN ? AND ?
        )))
        ORDER BY ts ASC LIMIT 100
        """,
        (start, end, device, device, dest, dest, device, start, end),
    ).fetchall()
    for row in rows:
        label = f"{row[2]} {row[3] or row[7] or row[6] or ''}".strip()
        add_incident_event(con, incident_id, "threat_correlations", row[0], row[1], "threat_intel", label, f"Threat-intel correlation from {row[4] or 'local feed'}: {row[5] or 'matched indicator'}.")
    rows = con.execute(
        """
        SELECT id, ts, remote_ip, category, total_mb
        FROM remote_traffic_intervals
        WHERE ts BETWEEN ? AND ? AND ((ip=? AND ?<>'') OR (remote_ip=? AND ?<>''))
        ORDER BY ts ASC LIMIT 100
        """,
        (start, end, device, device, dest, dest),
    ).fetchall()
    for row in rows:
        add_incident_event(con, incident_id, "remote_traffic_intervals", row[0], row[1], "traffic", f"{row[4] or 0:.3f} MB to {row[2]}", "Connection/traffic evidence matched device or destination in the investigation window.")
    for row in con.execute("SELECT alert_key, last_sent_ts FROM ids_alert_notifications WHERE alert_key LIKE ?", (f"%{signature}%",)).fetchall():
        try:
            ts = dt_text(datetime.fromtimestamp(int(row[1] or 0)))
        except Exception:
            ts = ""
        add_incident_event(con, incident_id, "ids_alert_notifications", row[0], ts, "notification", "IDS notification sent", "Notification state references the same IDS signature.")
    con.execute(
        """
        UPDATE security_incidents
        SET first_event_ts=(SELECT MIN(event_ts) FROM security_incident_events WHERE incident_id=? AND event_ts<>''),
            last_event_ts=(SELECT MAX(event_ts) FROM security_incident_events WHERE incident_id=? AND event_ts<>''),
            updated_at=?
        WHERE id=?
        """,
        (incident_id, incident_id, now_text(), incident_id),
    )


def build_incidents_once(connect_db, config):
    severities = {int(v) for v in config.get("incident_trigger_severities", [1, 2])}
    con = connect_db()
    con.row_factory = None
    ensure_schema(con)
    placeholders = ",".join("?" for _ in severities)
    raw_rows = con.execute(
        f"""
        SELECT * FROM ids_events
        WHERE event_type='alert' AND severity IN ({placeholders})
        ORDER BY id ASC LIMIT 500
        """,
        tuple(severities),
    ).fetchall()
    columns = [desc[0] for desc in con.execute("SELECT * FROM ids_events LIMIT 0").description]
    created = 0
    for raw in raw_rows:
        row = dict(zip(columns, raw))
        incident_id, was_created = find_or_create_incident(con, row, config)
        if not incident_id:
            continue
        correlate_alert(con, incident_id, row, config)
        if was_created:
            created += 1
    con.commit()
    con.close()
    return created


def prune_incidents(connect_db, config):
    days = int(config.get("incident_retention_days", 365) or 365)
    max_rows = int(config.get("incident_max_records", 50000) or 50000)
    min_free_mb = int(config.get("incident_min_free_mb", 512) or 512)
    con = connect_db()
    ensure_schema(con)
    cutoff = dt_text(datetime.now() - timedelta(days=days))
    con.execute("DELETE FROM security_incidents WHERE status='closed' AND updated_at<?", (cutoff,))
    count = con.execute("SELECT COUNT(*) FROM security_incidents").fetchone()[0]
    if count > max_rows:
        trim = count - max_rows
        ids = [row[0] for row in con.execute("SELECT id FROM security_incidents ORDER BY updated_at ASC LIMIT ?", (trim,)).fetchall()]
        if ids:
            placeholders = ",".join("?" for _ in ids)
            con.execute(f"DELETE FROM security_incidents WHERE id IN ({placeholders})", ids)
    existing = {row[0] for row in con.execute("SELECT id FROM security_incidents").fetchall()}
    for table in ("security_incident_events", "security_incident_notes", "security_incident_audit"):
        if existing:
            placeholders = ",".join("?" for _ in existing)
            con.execute(f"DELETE FROM {table} WHERE incident_id NOT IN ({placeholders})", tuple(existing))
        else:
            con.execute(f"DELETE FROM {table}")
    try:
        free_mb = shutil.disk_usage(str(DATA_ROOT)).free / 1024 / 1024
    except Exception:
        free_mb = min_free_mb + 1
    if free_mb < min_free_mb:
        con.execute("DELETE FROM security_incident_events WHERE id IN (SELECT id FROM security_incident_events ORDER BY event_ts ASC LIMIT 1000)")
    con.commit()
    con.close()


def list_incidents(connect_db, limit=200):
    con = connect_db()
    con.row_factory = None
    ensure_schema(con)
    rows = con.execute(
        """
        SELECT id, severity, device_ip, device_mac, device_name, first_event_ts, last_event_ts, status, assigned_to, title
        FROM security_incidents
        ORDER BY updated_at DESC, id DESC LIMIT ?
        """,
        (int(limit),),
    ).fetchall()
    con.close()
    return rows


def incident_detail(connect_db, incident_id):
    con = connect_db()
    con.row_factory = None
    ensure_schema(con)
    incident = con.execute("SELECT * FROM security_incidents WHERE id=?", (int(incident_id),)).fetchone()
    events = con.execute("SELECT source_table, source_id, event_ts, event_type, summary, reason FROM security_incident_events WHERE incident_id=? ORDER BY event_ts ASC, id ASC", (int(incident_id),)).fetchall()
    notes = con.execute("SELECT id, ts, author, note FROM security_incident_notes WHERE incident_id=? ORDER BY id DESC", (int(incident_id),)).fetchall()
    audit_rows = con.execute("SELECT ts, action, actor, detail FROM security_incident_audit WHERE incident_id=? ORDER BY id ASC", (int(incident_id),)).fetchall()
    related = {
        "domains": sorted({row[4] for row in events if row[3] in ("dns_query", "threat_intel") and row[4]}),
        "ips": [],
        "signatures": sorted({row[4] for row in events if row[3] == "suricata_alert" and row[4]}),
    }
    con.close()
    return incident, events, notes, audit_rows, related


def update_incident(connect_db, incident_id, status=None, assigned_to=None, note=None, actor="analyst"):
    con = connect_db()
    ensure_schema(con)
    if status:
        fields = ["status=?", "updated_at=?"]
        params = [status[:40], now_text()]
        if status == "closed":
            fields.append("closed_at=?")
            params.append(now_text())
        params.append(int(incident_id))
        con.execute(f"UPDATE security_incidents SET {', '.join(fields)} WHERE id=?", params)
        audit(con, incident_id, "status", f"Status set to {status}.", actor)
    if assigned_to is not None:
        con.execute("UPDATE security_incidents SET assigned_to=?, updated_at=? WHERE id=?", (assigned_to[:120], now_text(), int(incident_id)))
        audit(con, incident_id, "assigned", f"Assigned to {assigned_to}.", actor)
    if note:
        con.execute("INSERT INTO security_incident_notes (incident_id, ts, author, note) VALUES (?, ?, ?, ?)", (int(incident_id), now_text(), actor[:80], note[:2000]))
        audit(con, incident_id, "note", "Analyst note added.", actor)
    con.commit()
    con.close()
