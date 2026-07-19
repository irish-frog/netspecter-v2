import json
from datetime import datetime

from .paths import vault_root


def history_path():
    return vault_root() / "history.jsonl"


def record_event(action, status, detail="", archive="", size_bytes=0, sha256=""):
    row = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": str(action or ""),
        "status": str(status or ""),
        "detail": str(detail or ""),
        "archive": str(archive or ""),
        "size_bytes": int(size_bytes or 0),
        "sha256": str(sha256 or ""),
    }
    path = history_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def recent_events(limit=50):
    path = history_path()
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(errors="replace").splitlines()[-limit:]:
        try:
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
        except Exception:
            continue
    return list(reversed(rows))

def last_successful_scheduled_backup():
    for row in recent_events(500):
        if row.get("action") == "scheduled-backup" and row.get("status") == "ok":
            return row
    return None

