#!/usr/bin/env python3
import time
import sqlite3

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
