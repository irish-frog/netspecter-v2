import sqlite3
from pathlib import Path


def snapshot_sqlite_database(source, destination):
    """Create a consistent SQLite snapshot using SQLite's backup API."""
    source = Path(source)
    destination = Path(destination)
    if not source.exists():
        return False

    destination.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(str(source), timeout=30)
    try:
        dest = sqlite3.connect(str(destination), timeout=30)
        try:
            src.backup(dest)
            dest.execute("PRAGMA wal_checkpoint(FULL)")
            dest.commit()
        finally:
            dest.close()
    finally:
        src.close()
    return True


def sqlite_integrity_ok(path):
    path = Path(path)
    if not path.exists() or path.stat().st_size <= 0:
        return False, "database snapshot missing or empty"
    try:
        con = sqlite3.connect(str(path), timeout=30)
        try:
            rows = con.execute("PRAGMA integrity_check").fetchall()
        finally:
            con.close()
    except Exception as error:
        return False, str(error)
    ok = len(rows) == 1 and str(rows[0][0]).lower() == "ok"
    return ok, "ok" if ok else "; ".join(str(row[0]) for row in rows)

