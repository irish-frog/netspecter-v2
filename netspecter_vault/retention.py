import json
import tarfile
from datetime import datetime
from pathlib import Path

from .paths import backup_dir


def backup_metadata(path):
    path = Path(path)
    try:
        with tarfile.open(path, "r:gz") as tar:
            member = tar.extractfile("metadata.json")
            if not member:
                return None
            data = json.loads(member.read().decode("utf-8"))
            if int(data.get("backup_format_version", -1)) < 1:
                return None
            created = datetime.fromisoformat(str(data.get("created_at", "")).replace("Z", "+00:00"))
            return {"path": path, "metadata": data, "created": created}
    except Exception:
        return None


def recognised_backups(directory=None):
    directory = Path(directory) if directory else backup_dir()
    rows = []
    if not directory.exists():
        return rows
    for path in directory.glob("*.nsbackup"):
        meta = backup_metadata(path)
        if meta:
            rows.append(meta)
    return sorted(rows, key=lambda row: row["created"], reverse=True)


def retention_keep_set(backups, daily=7, weekly=4, monthly=6):
    keep = set()
    if not backups:
        return keep

    # Always keep the newest valid backup, even if settings are bad.
    keep.add(backups[0]["path"])

    daily_seen = set()
    weekly_seen = set()
    monthly_seen = set()
    for row in backups:
        created = row["created"]
        if len(daily_seen) < max(1, int(daily)):
            key = created.date().isoformat()
            if key not in daily_seen:
                daily_seen.add(key)
                keep.add(row["path"])
        if len(weekly_seen) < max(1, int(weekly)):
            iso = created.isocalendar()
            key = f"{iso.year}-W{iso.week:02d}"
            if key not in weekly_seen:
                weekly_seen.add(key)
                keep.add(row["path"])
        if len(monthly_seen) < max(1, int(monthly)):
            key = f"{created.year}-{created.month:02d}"
            if key not in monthly_seen:
                monthly_seen.add(key)
                keep.add(row["path"])
    return keep


def apply_retention(directory=None, daily=7, weekly=4, monthly=6, dry_run=False):
    backups = recognised_backups(directory)
    keep = retention_keep_set(backups, daily=daily, weekly=weekly, monthly=monthly)
    deleted = []
    for row in backups:
        path = row["path"]
        if path in keep:
            continue
        deleted.append(path)
        if not dry_run:
            path.unlink()
    return {"kept": sorted(keep), "deleted": deleted}

