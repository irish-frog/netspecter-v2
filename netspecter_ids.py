import json
import os
import re
import shutil
import sqlite3
import time
from datetime import datetime
from pathlib import Path


SURICATA_FAST_PATTERN = re.compile(
    r"^(?P<ts>\S+)\s+\[\*\*\]\s+\[(?P<sid>[^\]]+)\]\s+"
    r"(?P<signature>.*?)\s+\[\*\*\]\s+\[Classification:\s*(?P<classification>.*?)\]\s+"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+\{(?P<protocol>[^}]+)\}\s+"
    r"(?P<source>\S+)\s+->\s+(?P<destination>\S+)$"
)

STRUCTURED_TYPES = {"alert", "dns", "http", "tls", "fileinfo", "anomaly"}
TEXT_LIMITS = {
    "signature": 260,
    "category": 180,
    "query": 260,
    "answer_summary": 500,
    "hostname": 260,
    "url_path": 500,
    "user_agent": 260,
    "cert_subject": 260,
    "cert_issuer": 260,
    "filename": 260,
    "mime_type": 120,
    "hashes": 420,
    "anomaly_event": 220,
    "app_proto": 60,
    "protocol": 24,
    "event_type": 24,
}

DEFAULT_HIDDEN_SIGNATURES = {
    "SURICATA AF-PACKET truncated packet",
    "SURICATA IPv4 truncated packet",
}

DEFAULT_INFORMATIONAL_SIGNATURES = {
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)",
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Response)",
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Request On Non-Standard High Port)",
}

DEFAULT_SUPPRESSED_SIGNATURES = DEFAULT_HIDDEN_SIGNATURES | DEFAULT_INFORMATIONAL_SIGNATURES


def normalized_signature(value):
    return str(value or "").strip()


def is_default_hidden_signature(value):
    return normalized_signature(value) in DEFAULT_HIDDEN_SIGNATURES


def is_default_informational_signature(value):
    return normalized_signature(value) in DEFAULT_INFORMATIONAL_SIGNATURES


def is_default_suppressed_signature(value):
    return normalized_signature(value) in DEFAULT_SUPPRESSED_SIGNATURES


def effective_alert_severity(signature, severity):
    if is_default_informational_signature(signature):
        return 4
    return severity


def cap(value, limit=180):
    text = str(value or "").replace("\x00", "").strip()
    text = re.sub(r"[\r\n\t]+", " ", text)
    return text[:limit]


def cap_field(name, value):
    return cap(value, TEXT_LIMITS.get(name, 180))


def int_or_none(value):
    try:
        if value in ("", None):
            return None
        return int(value)
    except Exception:
        return None


def endpoint(host, port):
    host = cap(host, 80)
    port = int_or_none(port)
    return f"{host}:{port}" if host and port is not None else host


def ids_endpoint_ip(endpoint_text):
    text = str(endpoint_text or "").strip()
    if text.count(":") == 1:
        return text.rsplit(":", 1)[0]
    return text


def day_from_ts(ts):
    text = str(ts or "")
    if len(text) >= 10 and text[4:5] == "-" and text[7:8] == "-":
        return text[:10]
    return datetime.now().strftime("%Y-%m-%d")


def sid_parts(alert):
    gid = int_or_none(alert.get("gid")) or 1
    sid = int_or_none(alert.get("signature_id"))
    rev = int_or_none(alert.get("rev")) or 1
    return gid, sid, rev


def event_key(event, normalized):
    parts = [
        normalized.get("ts"),
        normalized.get("event_type"),
        normalized.get("flow_id"),
        normalized.get("src_ip"),
        normalized.get("src_port"),
        normalized.get("dest_ip"),
        normalized.get("dest_port"),
        normalized.get("signature_id"),
        normalized.get("query"),
        normalized.get("url_path"),
        normalized.get("filename"),
        normalized.get("anomaly_event"),
    ]
    return "|".join(cap(part, 120) for part in parts if part not in (None, ""))


def dns_answer_summary(dns):
    answers = dns.get("answers")
    if not isinstance(answers, list):
        return cap_field("answer_summary", dns.get("rdata") or "")
    summary = []
    for answer in answers[:8]:
        if not isinstance(answer, dict):
            continue
        summary.append(cap(answer.get("rrname") or answer.get("rdata") or answer.get("type"), 80))
    return cap_field("answer_summary", ", ".join(item for item in summary if item))


def hash_summary(fileinfo):
    hashes = fileinfo.get("hashes")
    if not isinstance(hashes, dict):
        return ""
    parts = []
    for key in ("md5", "sha1", "sha256"):
        if hashes.get(key):
            parts.append(f"{key}:{cap(hashes.get(key), 96)}")
    return cap_field("hashes", " ".join(parts))


def normalize_eve_event(event):
    if not isinstance(event, dict):
        return None
    event_type = cap_field("event_type", event.get("event_type"))
    if event_type not in STRUCTURED_TYPES:
        return None
    row = {
        "event_key": "",
        "event_type": event_type,
        "ts": cap(event.get("timestamp") or datetime.now().isoformat(timespec="seconds"), 40),
        "day": "",
        "src_ip": cap(event.get("src_ip"), 80),
        "src_port": int_or_none(event.get("src_port")),
        "dest_ip": cap(event.get("dest_ip"), 80),
        "dest_port": int_or_none(event.get("dest_port")),
        "protocol": cap_field("protocol", event.get("proto")),
        "app_proto": cap_field("app_proto", event.get("app_proto")),
        "flow_id": cap(event.get("flow_id"), 80),
        "signature_id": None,
        "signature": "",
        "category": "",
        "severity": None,
        "query": "",
        "query_type": "",
        "rcode": "",
        "answer_summary": "",
        "hostname": "",
        "method": "",
        "url_path": "",
        "user_agent": "",
        "status": None,
        "tls_sni": "",
        "tls_version": "",
        "cert_subject": "",
        "cert_issuer": "",
        "ja3": "",
        "ja4": "",
        "filename": "",
        "file_size": None,
        "mime_type": "",
        "hashes": "",
        "stored": 0,
        "anomaly_event": "",
    }
    row["day"] = day_from_ts(row["ts"])
    if event_type == "alert":
        alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
        _gid, sid, _rev = sid_parts(alert)
        row.update({
            "signature_id": sid,
            "signature": cap_field("signature", alert.get("signature")),
            "category": cap_field("category", alert.get("category")),
            "severity": int_or_none(alert.get("severity")),
        })
    elif event_type == "dns":
        dns = event.get("dns") if isinstance(event.get("dns"), dict) else {}
        row.update({
            "query": cap_field("query", dns.get("rrname") or dns.get("query")),
            "query_type": cap(dns.get("rrtype") or dns.get("type"), 40),
            "rcode": cap(dns.get("rcode"), 40),
            "answer_summary": dns_answer_summary(dns),
        })
    elif event_type == "http":
        http = event.get("http") if isinstance(event.get("http"), dict) else {}
        row.update({
            "hostname": cap_field("hostname", http.get("hostname")),
            "method": cap(http.get("http_method"), 20),
            "url_path": cap_field("url_path", http.get("url")),
            "user_agent": cap_field("user_agent", http.get("http_user_agent")),
            "status": int_or_none(http.get("status")),
        })
    elif event_type == "tls":
        tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
        row.update({
            "tls_sni": cap_field("hostname", tls.get("sni")),
            "tls_version": cap(tls.get("version"), 60),
            "cert_subject": cap_field("cert_subject", tls.get("subject")),
            "cert_issuer": cap_field("cert_issuer", tls.get("issuerdn")),
            "ja3": cap(tls.get("ja3") or tls.get("ja3_hash"), 80),
            "ja4": cap(tls.get("ja4"), 80),
        })
    elif event_type == "fileinfo":
        fileinfo = event.get("fileinfo") if isinstance(event.get("fileinfo"), dict) else {}
        row.update({
            "filename": cap_field("filename", fileinfo.get("filename")),
            "file_size": int_or_none(fileinfo.get("size")),
            "mime_type": cap_field("mime_type", fileinfo.get("magic") or fileinfo.get("mimetype")),
            "hashes": hash_summary(fileinfo),
            "stored": 1 if fileinfo.get("stored") else 0,
        })
    elif event_type == "anomaly":
        anomaly = event.get("anomaly") if isinstance(event.get("anomaly"), dict) else {}
        row["anomaly_event"] = cap_field("anomaly_event", anomaly.get("event") or anomaly.get("type"))
    row["event_key"] = event_key(event, row)
    return row if row["event_key"] else None


def fast_log_alerts_from_text(text, limit=300):
    alerts = []
    for line in reversed(str(text or "").splitlines()[-limit:]):
        match = SURICATA_FAST_PATTERN.match(line.strip())
        if match:
            alert = match.groupdict()
            alert["alert_status"] = "open"
            alerts.append(alert)
    return alerts


def row_value(row, key, default=None):
    try:
        return row[key]
    except (IndexError, KeyError):
        return default


def structured_alert_from_row(row):
    source = endpoint(row["src_ip"], row["src_port"])
    destination = endpoint(row["dest_ip"], row["dest_port"])
    sid = row["signature_id"] or ""
    effective_severity = effective_alert_severity(row["signature"], row["severity"] or 3)
    return {
        "id": row["id"],
        "ts": row["ts"],
        "sid": f"1:{sid}:1" if sid else "",
        "signature": row["signature"] or "Suricata alert",
        "classification": row["category"] or "",
        "priority": str(effective_severity or 3),
        "protocol": row["protocol"] or "",
        "source": source,
        "destination": destination,
        "source_ip": row["src_ip"] or ids_endpoint_ip(source),
        "destination_ip": row["dest_ip"] or ids_endpoint_ip(destination),
        "event_type": row["event_type"],
        "flow_id": row["flow_id"] or "",
        "alert_status": row_value(row, "alert_status", "open") or "open",
    }


def structured_event_summary_from_row(row):
    source = endpoint(row["src_ip"], row["src_port"])
    destination = endpoint(row["dest_ip"], row["dest_port"])
    event_type = row["event_type"] or "event"
    detail = (
        row["signature"] or row["query"] or row["hostname"] or row["tls_sni"] or
        row["filename"] or row["anomaly_event"] or event_type
    )
    classification = row["category"] or row["app_proto"] or row["mime_type"] or ""
    return {
        "id": row["id"],
        "ts": row["ts"],
        "sid": str(row["signature_id"] or ""),
        "signature": f"{event_type.upper()}: {detail}",
        "classification": classification,
        "priority": str(row["severity"] or 3),
        "protocol": row["protocol"] or row["app_proto"] or "",
        "source": source,
        "destination": destination,
        "source_ip": row["src_ip"] or ids_endpoint_ip(source),
        "destination_ip": row["dest_ip"] or ids_endpoint_ip(destination),
        "event_type": event_type,
        "flow_id": row["flow_id"] or "",
    }


def recent_structured_alerts(connect_db, limit=300, filters=None):
    filters = filters or {}
    where = ["event_type='alert'"]
    params = []
    show_default_noise = bool(filters.get("show_noise") or filters.get("show_default_noise"))
    hidden_signatures = [] if show_default_noise else sorted(DEFAULT_HIDDEN_SIGNATURES)
    for signature in hidden_signatures:
        where.append("signature<>?")
        params.append(signature)
    if not show_default_noise and not str(filters.get("severity", "") or "").strip():
        where.append("CAST(COALESCE(severity, 3) AS INTEGER) IN (1, 2)")
    mapping = {
        "severity": "severity=?",
        "event_type": "event_type=?",
        "protocol": "protocol=?",
        "destination": "dest_ip=?",
        "signature": "signature LIKE ?",
        "device": "src_ip=?",
    }
    for key, clause in mapping.items():
        value = str(filters.get(key, "") or "").strip()
        if not value:
            continue
        where.append(clause)
        params.append(f"%{value}%" if key == "signature" else value)
    alert_status = str(filters.get("alert_status") or filters.get("status") or "").strip()
    if alert_status:
        where.append("COALESCE(alert_status, 'open')=?")
        params.append(alert_status)
    sort = str(filters.get("sort") or "newest").strip().lower()
    order_by = {
        "newest": "ts DESC, id DESC",
        "oldest": "ts ASC, id ASC",
        "severity_high": "COALESCE(severity, 99) ASC, ts DESC, id DESC",
        "severity_low": "COALESCE(severity, 99) DESC, ts DESC, id DESC",
    }.get(sort, "ts DESC, id DESC")
    sql = f"SELECT * FROM ids_events WHERE {' AND '.join(where)} ORDER BY {order_by} LIMIT ?"
    params.append(int(limit))
    con = connect_db()
    con.row_factory = sqlite3.Row
    rows = con.execute(sql, params).fetchall()
    con.close()
    return [structured_alert_from_row(row) for row in rows]


VALID_ALERT_STATUSES = {"open", "acknowledged", "investigating", "closed", "ignored", "suppressed", "banned"}


def update_alert_status(connect_db, event_id, status):
    status = str(status or "").strip().lower()
    if status not in VALID_ALERT_STATUSES:
        raise ValueError("Invalid IDS alert status")
    con = connect_db()
    con.execute(
        "UPDATE ids_events SET alert_status=? WHERE id=? AND event_type='alert'",
        (status, int(event_id)),
    )
    con.commit()
    changed = con.total_changes
    con.close()
    return changed > 0


def delete_alert(connect_db, event_id):
    con = connect_db()
    con.execute("DELETE FROM ids_events WHERE id=? AND event_type='alert'", (int(event_id),))
    con.commit()
    changed = con.total_changes
    con.close()
    return changed > 0


def recent_structured_events(connect_db, limit=300, filters=None):
    filters = filters or {}
    where = []
    params = []
    for key, column in [("severity", "severity"), ("event_type", "event_type"), ("protocol", "protocol"), ("destination", "dest_ip"), ("device", "src_ip")]:
        value = str(filters.get(key, "") or "").strip()
        if value:
            where.append(f"{column}=?")
            params.append(value)
    signature = str(filters.get("signature", "") or "").strip()
    if signature:
        where.append("signature LIKE ?")
        params.append(f"%{signature}%")
    sql = "SELECT * FROM ids_events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(int(limit))
    con = connect_db()
    con.row_factory = sqlite3.Row
    rows = con.execute(sql, params).fetchall()
    con.close()
    return rows


def recent_structured_event_summaries(connect_db, limit=300, filters=None):
    return [structured_event_summary_from_row(row) for row in recent_structured_events(connect_db, limit, filters)]


def ingest_eve_incremental(connect_db, eve_path, batch_size=500):
    path = Path(eve_path)
    if not path.exists():
        return {"inserted": 0, "error": "Suricata eve.json was not found."}
    stat = path.stat()
    con = connect_db()
    con.row_factory = sqlite3.Row
    state = con.execute("SELECT * FROM ids_eve_state WHERE id=1").fetchone()
    inode = int(getattr(stat, "st_ino", 0) or 0)
    size = int(stat.st_size)
    offset = 0
    if state and int(state["inode"] or 0) == inode and int(state["offset"] or 0) <= size:
        offset = int(state["offset"] or 0)
    inserted = 0
    bad_json = 0
    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        for line in handle:
            try:
                normalized = normalize_eve_event(json.loads(line))
            except json.JSONDecodeError:
                bad_json += 1
                continue
            except Exception:
                continue
            if normalized:
                rows.append(normalized)
            if len(rows) >= batch_size:
                inserted += insert_events(con, rows)
                rows = []
        new_offset = handle.tell()
    if rows:
        inserted += insert_events(con, rows)
    con.execute(
        """
        INSERT INTO ids_eve_state (id, inode, offset, path, updated_at)
        VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, path=excluded.path, updated_at=excluded.updated_at
        """,
        (inode, new_offset, str(path), int(time.time())),
    )
    con.commit()
    con.close()
    return {"inserted": inserted, "bad_json": bad_json, "offset": new_offset, "inode": inode}


def insert_events(con, rows):
    columns = [
        "event_key", "event_type", "ts", "day", "src_ip", "src_port", "dest_ip", "dest_port",
        "protocol", "app_proto", "flow_id", "signature_id", "signature", "category", "severity",
        "query", "query_type", "rcode", "answer_summary", "hostname", "method", "url_path",
        "user_agent", "status", "tls_sni", "tls_version", "cert_subject", "cert_issuer", "ja3",
        "ja4", "filename", "file_size", "mime_type", "hashes", "stored", "anomaly_event",
    ]
    sql = f"INSERT OR IGNORE INTO ids_events ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
    before = con.total_changes
    con.executemany(sql, [[row.get(column) for column in columns] for row in rows])
    return con.total_changes - before


def prune_ids_history(connect_db, config):
    alert_days = max(1, int(config.get("ids_alert_retention_days", 60) or 60))
    detail_days = max(1, int(config.get("ids_detail_retention_days", 14) or 14))
    file_days = max(1, int(config.get("ids_file_retention_days", 30) or 30))
    max_rows = max(1000, int(config.get("ids_structured_max_records", 200000) or 200000))
    min_free_mb = max(0, int(config.get("ids_min_free_mb", 512) or 512))
    con = connect_db()
    con.execute("DELETE FROM ids_events WHERE event_type='alert' AND day < date('now', 'localtime', ?)", (f"-{alert_days - 1} days",))
    con.execute("DELETE FROM ids_events WHERE event_type IN ('dns','http','tls','anomaly') AND day < date('now', 'localtime', ?)", (f"-{detail_days - 1} days",))
    con.execute("DELETE FROM ids_events WHERE event_type='fileinfo' AND day < date('now', 'localtime', ?)", (f"-{file_days - 1} days",))
    total = con.execute("SELECT COUNT(*) FROM ids_events").fetchone()[0]
    if total > max_rows:
        trim = total - max_rows
        con.execute("DELETE FROM ids_events WHERE id IN (SELECT id FROM ids_events ORDER BY ts ASC, id ASC LIMIT ?)", (trim,))
    con.commit()
    con.close()
    free_mb = min_free_mb + 1
    try:
        con = connect_db()
        db_file = con.execute("PRAGMA database_list").fetchone()[2]
        con.close()
        free_mb = shutil.disk_usage(str(Path(db_file).parent)).free // 1024 // 1024
    except Exception:
        pass
    if free_mb < min_free_mb:
        con = connect_db()
        con.execute("DELETE FROM ids_events WHERE id IN (SELECT id FROM ids_events ORDER BY ts ASC, id ASC LIMIT 5000)")
        con.commit()
        con.close()


def maybe_vacuum_ids(connect_db):
    now = datetime.now()
    if 1 <= now.hour <= 4:
        con = connect_db()
        con.execute("VACUUM")
        con.close()
