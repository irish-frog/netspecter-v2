#!/usr/bin/env python3
import shutil
import subprocess
import time
import sqlite3
from datetime import datetime
from pathlib import Path

from app import (
    cfg,
    check_monitor_service,
    connect_db,
    init_db,
    monitor_key,
    normalise_gatus_monitors,
    recent_suricata_alerts,
    record_monitor_event,
    send_telegram_message,
)
from netspecter_ids import recent_structured_alerts


FAILURE_THRESHOLD = 2
SUCCESS_THRESHOLD = 2
IDS_PRIORITY_THRESHOLD = 2
MB = 1024 * 1024
GB = 1024 * MB
SURICATA_LOG_DIR = Path("/var/log/suricata")
SURICATA_LOGROTATE_CONFIG = Path("/etc/logrotate.d/suricata")
SURICATA_LOG_THRESHOLDS = {
    "eve.json": {"warning": 250 * MB, "critical": 1 * GB},
    "fast.log": {"warning": 50 * MB, "critical": 250 * MB},
}
SURICATA_TOTAL_THRESHOLDS = {"warning": 2 * GB, "critical": 5 * GB}
SURICATA_ROTATION_MAX_AGE_HOURS = 36
SURICATA_INCIDENT_KEY = "system|suricata-log-growth"


def is_locked_error(error):
    return isinstance(error, sqlite3.OperationalError) and "locked" in str(error).lower()


def sweeper_db():
    con = connect_db()
    con.execute("PRAGMA busy_timeout=500")
    return con


def ids_notification_recent(alert_key, now, cooldown):
    con = None
    try:
        con = sweeper_db()
        con.row_factory = sqlite3.Row
        row = con.execute(
            "SELECT last_sent_ts FROM ids_alert_notifications WHERE alert_key=?",
            (alert_key,),
        ).fetchone()
        return bool(row and now - int(row["last_sent_ts"] or 0) < cooldown)
    except sqlite3.OperationalError as error:
        if is_locked_error(error):
            print(f"IDS alert notification state read skipped: {error}")
            return True
        raise
    finally:
        if con:
            con.close()


def record_ids_notification_sent(alert_key, sent_ts):
    for attempt in range(3):
        con = sweeper_db()
        try:
            con.execute(
                """
                INSERT INTO ids_alert_notifications (alert_key, last_sent_ts)
                VALUES (?, ?)
                ON CONFLICT(alert_key) DO UPDATE SET last_sent_ts=excluded.last_sent_ts
                """,
                (alert_key, sent_ts),
            )
            con.commit()
            return True
        except sqlite3.OperationalError as error:
            con.rollback()
            if "locked" not in str(error).lower() or attempt == 2:
                print(f"IDS alert notification state update failed: {error}")
                return False
            time.sleep(0.5 * (attempt + 1))
        finally:
            con.close()
    return False


def ensure_state_table():
    con = None
    try:
        init_db()
        con = sweeper_db()
        con.row_factory = sqlite3.Row
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS monitor_alert_state (
                monitor_key TEXT PRIMARY KEY,
                name TEXT,
                url TEXT,
                state TEXT,
                fail_count INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                last_alert_state TEXT,
                updated_ts INTEGER
            )
            """
        )
        con.commit()
        return True
    except sqlite3.OperationalError as error:
        if is_locked_error(error):
            print(f"Monitor state table setup skipped: {error}")
            return False
        raise
    finally:
        if con:
            con.close()


def fetch_monitor_alert_state(key):
    con = None
    try:
        con = sweeper_db()
        con.row_factory = sqlite3.Row
        return con.execute(
            "SELECT * FROM monitor_alert_state WHERE monitor_key=?",
            (key,),
        ).fetchone()
    except sqlite3.OperationalError as error:
        if is_locked_error(error):
            print(f"Monitor alert state read skipped: {error}")
            return None
        raise
    finally:
        if con:
            con.close()


def save_monitor_alert_state(key, name, url, state, fail_count, success_count, last_alert_state):
    con = sweeper_db()
    try:
        con.execute(
            """
            INSERT INTO monitor_alert_state
                (monitor_key, name, url, state, fail_count, success_count, last_alert_state, updated_ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(monitor_key) DO UPDATE SET
                name=excluded.name,
                url=excluded.url,
                state=excluded.state,
                fail_count=excluded.fail_count,
                success_count=excluded.success_count,
                last_alert_state=excluded.last_alert_state,
                updated_ts=excluded.updated_ts
            """,
            (key, name, url, state, fail_count, success_count, last_alert_state, int(time.time())),
        )
        con.commit()
    except sqlite3.OperationalError as error:
        con.rollback()
        print(f"Monitor alert state update failed: {error}")
    finally:
        con.close()


def bytes_label(value):
    value = float(value or 0)
    if value >= GB:
        return f"{value / GB:.1f} GB"
    if value >= MB:
        return f"{value / MB:.1f} MB"
    return f"{value / 1024:.1f} KB"


def worst_severity(current, candidate):
    current = int(current or 0)
    candidate = int(candidate or 0)
    if current <= 0:
        return candidate
    if candidate <= 0:
        return current
    return min(current, candidate)


def systemctl_state(unit):
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", unit],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        enabled = (result.stdout or "").strip() or "unknown"
    except Exception:
        enabled = "unknown"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        active = (result.stdout or "").strip() or "unknown"
    except Exception:
        active = "unknown"
    return enabled, active


def suricata_log_inventory(log_dir=SURICATA_LOG_DIR):
    rows = []
    if not log_dir.exists():
        return rows
    for path in log_dir.rglob("*"):
        try:
            if not path.is_file():
                continue
            stat = path.stat()
            rows.append({"path": path, "name": path.name, "size": stat.st_size, "mtime": stat.st_mtime})
        except OSError:
            continue
    return rows


def newest_rotation_age_hours(log_dir=SURICATA_LOG_DIR, now=None):
    now = now or time.time()
    newest = None
    if not log_dir.exists():
        return None
    for path in log_dir.glob("*"):
        name = path.name
        if not (".log." in name or ".json." in name):
            continue
        try:
            if not path.is_file():
                continue
            mtime = path.stat().st_mtime
            newest = mtime if newest is None else max(newest, mtime)
        except OSError:
            continue
    if newest is None:
        return None
    return max(0, (now - newest) / 3600)


def assess_suricata_logs(now=None, log_dir=SURICATA_LOG_DIR, logrotate_config=SURICATA_LOGROTATE_CONFIG):
    now = now or time.time()
    files = suricata_log_inventory(log_dir)
    total_size = sum(row["size"] for row in files)
    largest = max(files, key=lambda row: row["size"], default={"name": "-", "size": 0})
    filesystem = {"percent": 0, "free": 0, "total": 0}
    try:
        usage_path = log_dir if log_dir.exists() else Path("/")
        usage = shutil.disk_usage(str(usage_path))
        filesystem = {
            "percent": round((usage.used / usage.total) * 100, 1) if usage.total else 0,
            "free": usage.free,
            "total": usage.total,
        }
    except Exception:
        pass
    enabled, active = systemctl_state("logrotate.timer")
    rotation_age = newest_rotation_age_hours(log_dir, now=now)
    issues = []
    max_severity = 0

    sizes = {row["name"]: row["size"] for row in files}
    for name, thresholds in SURICATA_LOG_THRESHOLDS.items():
        size = int(sizes.get(name, 0) or 0)
        if size >= thresholds["critical"]:
            issues.append(f"{name} is {bytes_label(size)}")
            max_severity = worst_severity(max_severity, 1)
        elif size >= thresholds["warning"]:
            issues.append(f"{name} is {bytes_label(size)}")
            max_severity = worst_severity(max_severity, 3)

    if total_size >= SURICATA_TOTAL_THRESHOLDS["critical"]:
        issues.append(f"Suricata log directory is {bytes_label(total_size)}")
        max_severity = worst_severity(max_severity, 1)
    elif total_size >= SURICATA_TOTAL_THRESHOLDS["warning"]:
        issues.append(f"Suricata log directory is {bytes_label(total_size)}")
        max_severity = worst_severity(max_severity, 3)

    if enabled != "enabled" or active != "active":
        issues.append(f"logrotate.timer is enabled={enabled}, active={active}")
        max_severity = worst_severity(max_severity, 3)
    if not logrotate_config.exists():
        issues.append("Suricata logrotate configuration is missing")
        max_severity = worst_severity(max_severity, 1)
    if total_size >= SURICATA_TOTAL_THRESHOLDS["warning"]:
        if rotation_age is None:
            issues.append("No recent rotated Suricata log files were found")
            max_severity = worst_severity(max_severity, 3)
        elif rotation_age > SURICATA_ROTATION_MAX_AGE_HOURS:
            issues.append(f"Last Suricata log rotation appears {rotation_age:.1f} hours old")
            max_severity = worst_severity(max_severity, 3)

    return {
        "ok": not issues,
        "severity": max_severity,
        "issues": issues,
        "largest_name": str(largest["name"]),
        "largest_size": int(largest["size"] or 0),
        "total_size": int(total_size),
        "filesystem": filesystem,
        "logrotate_enabled": enabled,
        "logrotate_active": active,
        "logrotate_config_exists": logrotate_config.exists(),
        "rotation_age_hours": rotation_age,
    }


def suricata_incident_summary(assessment):
    lines = [
        "Suricata logs are growing abnormally.",
        "",
        f"Largest file: {assessment['largest_name']}",
        f"File size: {bytes_label(assessment['largest_size'])}",
        f"Total Suricata logs: {bytes_label(assessment['total_size'])}",
        f"Disk usage: {assessment['filesystem']['percent']}%",
        f"Available space: {bytes_label(assessment['filesystem']['free'])}",
        f"logrotate.timer: enabled={assessment['logrotate_enabled']}, active={assessment['logrotate_active']}",
        f"Suricata logrotate config: {'present' if assessment['logrotate_config_exists'] else 'missing'}",
    ]
    if assessment["rotation_age_hours"] is not None:
        lines.append(f"Last detected rotation: {assessment['rotation_age_hours']:.1f} hours ago")
    if assessment["issues"]:
        lines.extend(["", "Checks:", *[f"- {issue}" for issue in assessment["issues"]]])
    lines.extend(["", "Check Suricata event volume and log rotation."])
    return "\n".join(lines)


def upsert_suricata_log_incident(assessment):
    con = None
    try:
        init_db()
        con = sweeper_db()
        con.row_factory = sqlite3.Row
        now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row = con.execute("SELECT id, status FROM security_incidents WHERE incident_key=?", (SURICATA_INCIDENT_KEY,)).fetchone()
        if assessment["ok"]:
            if row and str(row["status"] or "").lower() not in {"resolved", "closed"}:
                con.execute(
                    "UPDATE security_incidents SET status='resolved', updated_at=?, closed_at=? WHERE id=?",
                    (now_text, now_text, row["id"]),
                )
                con.execute(
                    "INSERT INTO security_incident_audit (incident_id, ts, action, actor, detail) VALUES (?, ?, 'resolved', 'system', ?)",
                    (row["id"], now_text, "Suricata log usage and rotation checks returned to normal."),
                )
            con.commit()
            return
        title = "Suricata log growth warning" if int(assessment["severity"] or 3) > 1 else "Suricata log growth critical"
        summary = suricata_incident_summary(assessment)
        if row:
            con.execute(
                """
                UPDATE security_incidents
                SET severity=?, last_event_ts=?, status=CASE WHEN status IN ('resolved', 'closed') THEN 'new' ELSE status END,
                    title=?, summary=?, updated_at=?, closed_at=NULL
                WHERE id=?
                """,
                (int(assessment["severity"] or 3), now_text, title, summary, now_text, row["id"]),
            )
            incident_id = row["id"]
        else:
            cur = con.execute(
                """
                INSERT INTO security_incidents
                    (incident_key, severity, device_ip, device_mac, device_name, first_event_ts, last_event_ts,
                     status, title, summary, anchor_event_id, created_at, updated_at)
                VALUES (?, ?, '', '', 'NetSpecter appliance', ?, ?, 'new', ?, ?, NULL, ?, ?)
                """,
                (SURICATA_INCIDENT_KEY, int(assessment["severity"] or 3), now_text, now_text, title, summary, now_text, now_text),
            )
            incident_id = cur.lastrowid
            con.execute(
                "INSERT INTO security_incident_audit (incident_id, ts, action, actor, detail) VALUES (?, ?, 'created', 'system', ?)",
                (incident_id, now_text, "Created from Suricata log self-monitoring."),
            )
        con.execute(
            """
            INSERT OR IGNORE INTO security_incident_events
                (incident_id, source_table, source_id, event_ts, event_type, summary, reason)
            VALUES (?, 'suricata_logs', ?, ?, 'suricata_log_health', ?, ?)
            """,
            (
                incident_id,
                str(int(time.time() // 300)),
                now_text,
                f"{assessment['largest_name']} {bytes_label(assessment['largest_size'])}; total {bytes_label(assessment['total_size'])}",
                "; ".join(assessment["issues"])[:500],
            ),
        )
        con.commit()
    except sqlite3.OperationalError as error:
        if is_locked_error(error):
            print(f"Suricata log incident update skipped: {error}")
            return
        raise
    finally:
        if con:
            con.close()


def sweep_suricata_logs():
    upsert_suricata_log_incident(assess_suricata_logs())


def sweep():
    if not ensure_state_table():
        return
    config = cfg()
    if not config.get("telegram_enabled"):
        return

    monitors = [m for m in normalise_gatus_monitors(config) if m.get("telegram")]
    pending_events = []
    for monitor in monitors:
        name = str(monitor.get("name", "Monitor") or "Monitor").strip()
        url = str(monitor.get("url", "") or "").strip()
        key = monitor_key(name, url)
        ok, _detail = check_monitor_service(monitor, timeout=2.0, brief=True)
        row = fetch_monitor_alert_state(key)
        fail_count = int(row["fail_count"] or 0) if row else 0
        success_count = int(row["success_count"] or 0) if row else 0
        last_alert_state = str(row["last_alert_state"] or "") if row else ""

        if ok:
            success_count += 1
            fail_count = 0
            state = "up"
        else:
            fail_count += 1
            success_count = 0
            state = "down"
        previous_state = str(row["state"] or "") if row else ""
        if previous_state != state:
            pending_events.append((name, url, state))

        should_send_down = not ok and fail_count >= FAILURE_THRESHOLD and last_alert_state != "down"
        should_send_up = ok and success_count >= SUCCESS_THRESHOLD and last_alert_state == "down"
        if should_send_down:
            sent, _ = send_telegram_message(config, f"NetSpecter Monitor\n{name} is offline.\nURL: {url}")
            if sent:
                last_alert_state = "down"
        elif should_send_up:
            sent, _ = send_telegram_message(config, f"NetSpecter Monitor\n{name} is back online.\nURL: {url}")
            if sent:
                last_alert_state = "up"

        save_monitor_alert_state(key, name, url, state, fail_count, success_count, last_alert_state)
    for name, url, state in pending_events:
        record_monitor_event(name, url, state)


def sweep_ids_alerts():
    config = cfg()
    if not config.get("ids_telegram_enabled") or not config.get("telegram_enabled"):
        return
    try:
        alerts = recent_structured_alerts(connect_db, limit=120, filters={"alert_status": "open"})
    except Exception:
        alerts = []
    if not alerts:
        alerts, _error = recent_suricata_alerts(limit=120)
    if not alerts:
        return
    cooldown = max(60, int(config.get("ids_email_cooldown_minutes", 480) or 480) * 60)
    now = int(time.time())
    init_db()
    for alert in alerts:
        if str(alert.get("alert_status") or "open").lower() != "open":
            continue
        try:
            priority = int(alert.get("priority") or 3)
        except Exception:
            priority = 3
        if priority > IDS_PRIORITY_THRESHOLD:
            continue
        key = "|".join([
            str(alert.get("sid", "")),
            str(alert.get("source", "")),
            str(alert.get("destination", "")),
            str(alert.get("signature", "")),
        ])
        if ids_notification_recent(key, now, cooldown):
            continue
        text = (
            f"NetSpecter IDS Alert\n"
            f"P{priority}: {alert.get('signature', 'Unknown alert')}\n"
            f"Source: {alert.get('source', '-')}\n"
            f"Destination: {alert.get('destination', '-')}"
        )
        sent, _ = send_telegram_message(config, text)
        if sent:
            record_ids_notification_sent(key, now)


if __name__ == "__main__":
    sweep()
    sweep_ids_alerts()
    sweep_suricata_logs()
