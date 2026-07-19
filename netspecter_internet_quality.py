import json
import shutil
import socket
import sqlite3
import statistics
import subprocess
import time
from datetime import datetime, timedelta

import netspecter_live_snapshot as live_snapshot
from netspecter_public_ip import lookup_public_ip_info


DEFAULT_TARGETS = ["1.1.1.1", "8.8.8.8"]
DEFAULT_DNS_QUERY = "example.com"


def positive_int(value, default, minimum=0, maximum=None):
    try:
        number = int(value)
    except Exception:
        number = default
    number = max(minimum, number)
    if maximum is not None:
        number = min(number, maximum)
    return number


def clean_target(value):
    text = str(value or "").strip()
    if not text:
        return ""
    return text[:120]


def quality_targets(config):
    values = config.get("internet_quality_targets", DEFAULT_TARGETS)
    if isinstance(values, str):
        values = [part.strip() for part in values.split(",")]
    targets = []
    for value in values if isinstance(values, list) else []:
        target = clean_target(value)
        if target and target not in targets:
            targets.append(target)
    for fallback in DEFAULT_TARGETS:
        if len(targets) >= 2:
            break
        if fallback not in targets:
            targets.append(fallback)
    return targets[:4]


def dns_server_from_config(config, external=False):
    if external:
        return clean_target(config.get("internet_quality_external_dns_server", "1.1.1.1")) or "1.1.1.1"
    value = clean_target(config.get("internet_quality_dns_server", ""))
    if value:
        return value
    adguard_url = str(config.get("adguard_url", "") or "").strip()
    if adguard_url:
        try:
            from urllib.parse import urlsplit
            parsed = urlsplit(adguard_url if "://" in adguard_url else f"http://{adguard_url}")
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass
    return "127.0.0.1"


def ensure_quality_schema(con):
    attached = {row[1] for row in con.execute("PRAGMA database_list").fetchall()}
    schema = "trafficdb" if "trafficdb" in attached else "main"
    table = f"{schema}.internet_quality" if schema != "main" else "internet_quality"
    index_prefix = f"{schema}." if schema != "main" else ""
    con.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            status TEXT NOT NULL,
            diagnosis TEXT,
            gateway_ip TEXT,
            gateway_latency_ms REAL,
            gateway_loss_pct REAL,
            internet_latency_ms REAL,
            internet_loss_pct REAL,
            jitter_ms REAL,
            dns_ms REAL,
            external_dns_ms REAL,
            wan_up INTEGER DEFAULT 0,
            targets_ok INTEGER DEFAULT 0,
            targets_total INTEGER DEFAULT 0,
            public_ip TEXT,
            isp_name TEXT,
            asn TEXT,
            isp_org TEXT,
            details TEXT
        )
        """
    )
    for column, definition in (
        ("public_ip", "TEXT"),
        ("isp_name", "TEXT"),
        ("asn", "TEXT"),
        ("isp_org", "TEXT"),
    ):
        try:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError as error:
            if "duplicate column" not in str(error).lower():
                raise
    con.execute(f"CREATE INDEX IF NOT EXISTS {index_prefix}idx_internet_quality_ts ON internet_quality(ts)")
    con.execute(f"CREATE INDEX IF NOT EXISTS {index_prefix}idx_internet_quality_status ON internet_quality(status)")
    con.execute(f"CREATE INDEX IF NOT EXISTS {index_prefix}idx_internet_quality_isp ON internet_quality(asn, isp_name, public_ip)")


def init_quality_db(connect_db):
    con = connect_db()
    ensure_quality_schema(con)
    con.commit()
    con.close()


def parse_ping_output(output, sent):
    text = output or ""
    received = 0
    for pattern in (r"(\d+)\s+received", r"Received\s*=\s*(\d+)"):
        match = __import__("re").search(pattern, text, __import__("re").IGNORECASE)
        if match:
            received = int(match.group(1))
            break
    latencies = [float(value) for value in __import__("re").findall(r"time[=<]\s*([0-9.]+)\s*ms", text, __import__("re").IGNORECASE)]
    if not latencies:
        latencies = [float(value) for value in __import__("re").findall(r"Average\s*=\s*([0-9.]+)ms", text, __import__("re").IGNORECASE)]
    if received == 0 and latencies:
        received = len(latencies)
    loss = max(0.0, min(100.0, (sent - min(received, sent)) / sent * 100.0))
    avg = round(sum(latencies) / len(latencies), 2) if latencies else None
    return {"ok": received > 0, "sent": sent, "received": received, "loss_pct": round(loss, 2), "latencies": latencies, "avg_ms": avg}


def ping_target(target, count=3, timeout=2):
    if not shutil.which("ping"):
        return {"ok": False, "error": "ping missing", "sent": count, "received": 0, "loss_pct": 100.0, "latencies": [], "avg_ms": None}
    command = ["ping", "-c", str(count), "-W", str(timeout), target]
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=count * timeout + 2, check=False)
        parsed = parse_ping_output(result.stdout, count)
        parsed["error"] = "" if parsed["ok"] else (result.stdout or "ping failed")[:180]
        return parsed
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "ping timeout", "sent": count, "received": 0, "loss_pct": 100.0, "latencies": [], "avg_ms": None}
    except Exception as error:
        return {"ok": False, "error": str(error)[:180], "sent": count, "received": 0, "loss_pct": 100.0, "latencies": [], "avg_ms": None}


def dns_query_ms(server, query_name=DEFAULT_DNS_QUERY, timeout=2):
    server = clean_target(server)
    query_name = clean_target(query_name) or DEFAULT_DNS_QUERY
    if not server:
        return {"ok": False, "ms": None, "error": "dns server missing"}
    start = time.monotonic()
    if shutil.which("dig"):
        try:
            result = subprocess.run(
                ["dig", f"@{server}", query_name, "A", "+tries=1", f"+time={max(1, int(timeout))}", "+short"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1,
                check=False,
            )
            elapsed = round((time.monotonic() - start) * 1000, 2)
            if result.returncode == 0 and (result.stdout or "").strip():
                return {"ok": True, "ms": elapsed, "error": ""}
            return {"ok": False, "ms": elapsed, "error": (result.stderr or result.stdout or "no answer")[:180]}
        except subprocess.TimeoutExpired:
            return {"ok": False, "ms": None, "error": "dns timeout"}
        except Exception as error:
            return {"ok": False, "ms": None, "error": str(error)[:180]}
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(query_name, 80)
        return {"ok": True, "ms": round((time.monotonic() - start) * 1000, 2), "error": "system resolver fallback"}
    except Exception as error:
        return {"ok": False, "ms": None, "error": f"dig missing; resolver failed: {error}"[:180]}


def mean(values):
    clean = [float(value) for value in values if value is not None]
    return round(sum(clean) / len(clean), 2) if clean else None


def calculate_jitter(latencies):
    """Jitter is mean absolute difference between consecutive successful ping RTTs."""
    values = [float(value) for value in latencies if value is not None]
    if len(values) < 2:
        return 0.0 if values else None
    diffs = [abs(values[index] - values[index - 1]) for index in range(1, len(values))]
    return round(statistics.mean(diffs), 2)


def diagnose(gateway, targets, dns_result):
    target_ok = sum(1 for item in targets if item.get("ok"))
    target_total = len(targets)
    gateway_ok = bool(gateway.get("ok")) if gateway else True
    dns_ok = bool(dns_result.get("ok"))
    internet_loss = mean([item.get("loss_pct") for item in targets])
    if internet_loss is None:
        internet_loss = 100.0
    internet_latency = mean([item.get("avg_ms") for item in targets])
    gateway_latency = gateway.get("avg_ms") if gateway else None
    gateway_loss = gateway.get("loss_pct") if gateway else 0.0

    if gateway and not gateway_ok:
        return "down", "Gateway unavailable: LAN, bridge or gateway problem."
    if target_total and target_ok == 0:
        return "down", "Gateway healthy but multiple internet targets fail: ISP/WAN problem."
    if target_total > 1 and target_ok == target_total - 1:
        return "warn", "One target fails: remote-host problem."
    if target_total > 1 and target_ok <= target_total // 2:
        return "warn", "Gateway healthy but multiple internet targets fail: ISP/WAN problem."
    if target_ok and not dns_ok:
        return "warn", "Internet healthy but DNS fails: DNS/AdGuard problem."
    if gateway_latency is not None and gateway_latency >= 50:
        return "warn", "Gateway latency also high: LAN congestion, bridge or gateway problem."
    if internet_loss >= 20 or (internet_latency is not None and internet_latency >= 180):
        return "warn", "Good gateway latency but poor internet latency/loss: ISP-quality problem."
    if gateway_loss and gateway_loss >= 20:
        return "warn", "Gateway latency also high: LAN congestion, bridge or gateway problem."
    return "ok", "WAN healthy."


def collect_quality_summary(config):
    ping_count = positive_int(config.get("internet_quality_ping_count", 3), 3, 1, 5)
    ping_timeout = positive_int(config.get("internet_quality_ping_timeout_seconds", 2), 2, 1, 5)
    gateway_ip = clean_target(config.get("gateway_ip", ""))
    gateway = ping_target(gateway_ip, ping_count, ping_timeout) if gateway_ip else None
    targets = []
    all_latencies = []
    for target in quality_targets(config):
        result = ping_target(target, ping_count, ping_timeout)
        result["target"] = target
        targets.append(result)
        all_latencies.extend(result.get("latencies") or [])
    dns_result = dns_query_ms(dns_server_from_config(config), config.get("internet_quality_dns_query", DEFAULT_DNS_QUERY), timeout=ping_timeout)
    external_dns = None
    if config.get("internet_quality_external_dns_enabled", True):
        external_dns = dns_query_ms(dns_server_from_config(config, external=True), config.get("internet_quality_dns_query", DEFAULT_DNS_QUERY), timeout=ping_timeout)
    jitter = calculate_jitter(all_latencies)
    status, diagnosis = diagnose(gateway, targets, dns_result)
    if status == "ok" and jitter is not None and jitter >= 50:
        status = "warn"
        diagnosis = "Good gateway latency but poor internet latency/loss: ISP-quality problem."
    public_info = lookup_public_ip_info(timeout=4)
    return {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "diagnosis": diagnosis,
        "gateway_ip": gateway_ip,
        "gateway_latency_ms": gateway.get("avg_ms") if gateway else None,
        "gateway_loss_pct": gateway.get("loss_pct") if gateway else None,
        "internet_latency_ms": mean([item.get("avg_ms") for item in targets]),
        "internet_loss_pct": mean([item.get("loss_pct") for item in targets]),
        "jitter_ms": jitter,
        "dns_ms": dns_result.get("ms") if dns_result.get("ok") else None,
        "external_dns_ms": external_dns.get("ms") if external_dns and external_dns.get("ok") else None,
        "wan_up": 1 if any(item.get("ok") for item in targets) else 0,
        "targets_ok": sum(1 for item in targets if item.get("ok")),
        "targets_total": len(targets),
        "public_ip": public_info.get("public_ip") or "",
        "isp_name": public_info.get("isp_name") or "",
        "asn": public_info.get("asn") or "",
        "isp_org": public_info.get("org") or "",
        "details": json.dumps({"gateway": gateway, "targets": targets, "dns": dns_result, "external_dns": external_dns, "public_ip": public_info}, separators=(",", ":"))[:4000],
    }


def insert_quality_summary(connect_db, summary):
    con = connect_db()
    ensure_quality_schema(con)
    con.execute(
        """
        INSERT INTO internet_quality
            (ts, status, diagnosis, gateway_ip, gateway_latency_ms, gateway_loss_pct,
             internet_latency_ms, internet_loss_pct, jitter_ms, dns_ms, external_dns_ms,
             wan_up, targets_ok, targets_total, public_ip, isp_name, asn, isp_org, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            summary["ts"], summary["status"], summary["diagnosis"], summary["gateway_ip"],
            summary["gateway_latency_ms"], summary["gateway_loss_pct"], summary["internet_latency_ms"],
            summary["internet_loss_pct"], summary["jitter_ms"], summary["dns_ms"], summary["external_dns_ms"],
            summary["wan_up"], summary["targets_ok"], summary["targets_total"],
            summary.get("public_ip", ""), summary.get("isp_name", ""), summary.get("asn", ""), summary.get("isp_org", ""),
            summary["details"],
        ),
    )
    con.commit()
    con.close()


def collect_and_store_quality(connect_db, config):
    summary = collect_quality_summary(config)
    live_snapshot.update_quality(summary)
    insert_quality_summary(connect_db, summary)
    return summary


def prune_quality_history(connect_db, config):
    retention_days = positive_int(config.get("internet_quality_retention_days", 30), 30, 1)
    max_rows = positive_int(config.get("internet_quality_max_rows", 50000), 50000, 1)
    min_free_mb = positive_int(config.get("internet_quality_min_free_mb", 512), 512, 0)
    con = connect_db()
    ensure_quality_schema(con)
    con.execute("DELETE FROM internet_quality WHERE ts < datetime('now', 'localtime', ?)", (f"-{retention_days} days",))
    total = con.execute("SELECT COUNT(*) FROM internet_quality").fetchone()[0]
    if total > max_rows:
        con.execute(
            "DELETE FROM internet_quality WHERE id IN (SELECT id FROM internet_quality ORDER BY ts ASC LIMIT ?)",
            (total - max_rows,),
        )
    try:
        usage = shutil.disk_usage(str(__import__("netspecter_paths").DATA_ROOT))
        free_mb = usage.free / 1024 / 1024
    except Exception:
        free_mb = min_free_mb + 1
    if free_mb < min_free_mb:
        total = con.execute("SELECT COUNT(*) FROM internet_quality").fetchone()[0]
        delete_count = max(total // 10, 100)
        con.execute(
            "DELETE FROM internet_quality WHERE id IN (SELECT id FROM internet_quality ORDER BY ts ASC LIMIT ?)",
            (delete_count,),
        )
    con.commit()
    con.close()


def maybe_vacuum_quality(connect_db):
    """Vacuum only during low-activity overnight hours after cleanup work."""
    hour = datetime.now().hour
    if hour < 2 or hour > 4:
        return False
    con = connect_db()
    try:
        con.isolation_level = None
        con.execute("VACUUM")
        return True
    finally:
        con.close()


def quality_history_start(connect_db):
    con = connect_db()
    ensure_quality_schema(con)
    row = con.execute("SELECT MIN(ts) AS first_ts FROM internet_quality").fetchone()
    con.close()
    if not row or not row[0]:
        return None
    try:
        return datetime.strptime(str(row[0])[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def recent_quality(connect_db, hours=24, limit=2000):
    hours = positive_int(hours, 24, 1, 24 * 365)
    start_dt = datetime.now() - timedelta(hours=hours)
    first_dt = quality_history_start(connect_db)
    if first_dt and first_dt > start_dt:
        start_dt = first_dt
    con = connect_db()
    con.row_factory = sqlite3.Row
    ensure_quality_schema(con)
    rows = con.execute(
        """
        SELECT * FROM internet_quality
        WHERE ts >= ?
        ORDER BY ts ASC
        LIMIT ?
        """,
        (start_dt.strftime("%Y-%m-%d %H:%M:%S"), int(limit)),
    ).fetchall()
    con.close()
    return rows


def latest_quality(connect_db):
    con = connect_db()
    con.row_factory = sqlite3.Row
    ensure_quality_schema(con)
    row = con.execute("SELECT * FROM internet_quality ORDER BY ts DESC LIMIT 1").fetchone()
    con.close()
    return row
