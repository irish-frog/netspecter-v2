"""Explicit cleanup of retired security-alert history, without traffic data."""

import sqlite3
from pathlib import Path


HISTORY_TABLES = (
    "security_incident_notes", "security_incident_audit", "security_incident_events",
    "security_incidents", "ids_alert_notifications", "anomaly_events", "threat_correlations",
)
LOG_PATTERNS = ("eve.json*", "fast.log*", "suricata.log*", "stats.log*")


def clear_database_history(path, apply=False):
    path = Path(path)
    if not path.is_file():
        return {}
    con = sqlite3.connect(path.resolve().as_uri() + ("?mode=rw" if apply else "?mode=ro"), uri=True)
    try:
        con.execute("PRAGMA busy_timeout=5000")
        if apply:
            con.execute("BEGIN IMMEDIATE")
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        counts = {}
        for table in HISTORY_TABLES:
            if table in tables:
                counts[table] = con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                if apply:
                    con.execute(f'DELETE FROM "{table}"')
        if "ids_events" in tables:
            counts["ids_alerts"] = con.execute("SELECT COUNT(*) FROM ids_events WHERE event_type='alert'").fetchone()[0]
            if apply:
                con.execute("DELETE FROM ids_events WHERE event_type='alert'")
        if apply:
            con.commit()
        return counts
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def clear_log_history(directory, apply=False):
    root = Path(directory).resolve()
    if not root.is_dir():
        return []
    paths = sorted({path for pattern in LOG_PATTERNS for path in root.glob(pattern)})
    removed = []
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.resolve().parent != root:
            continue
        removed.append(path.name)
        if apply:
            path.unlink()
    return removed
