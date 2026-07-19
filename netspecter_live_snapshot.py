import json
import os
import time
from copy import deepcopy
from datetime import datetime
from threading import RLock

from netspecter_paths import LIVE_SNAPSHOT_PATH


_LOCK = RLock()
_SNAPSHOT = {
    "updated_at": "",
    "speeds": {},
    "heartbeat": {},
    "quality": {},
    "summary": {},
}
_FILE_CACHE = {"mtime": 0.0, "loaded_at": 0.0, "data": None}


def _now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse_ts(value):
    try:
        return datetime.strptime(str(value or "")[:19], "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return 0.0


def _snapshot_age(data=None):
    source = data if data is not None else _SNAPSHOT
    ts = _parse_ts(source.get("updated_at"))
    return max(0.0, time.time() - ts) if ts else None


def _write_file_locked():
    payload = deepcopy(_SNAPSHOT)
    payload["snapshot_age_seconds"] = _snapshot_age(payload)
    try:
        LIVE_SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = LIVE_SNAPSHOT_PATH.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp_path, LIVE_SNAPSHOT_PATH)
    except Exception as error:
        print(f"Live snapshot write failed: {error}")


def _load_file_snapshot(max_cache_age=0.5):
    now = time.monotonic()
    cached = _FILE_CACHE.get("data")
    if cached is not None and now - float(_FILE_CACHE.get("loaded_at") or 0) < max_cache_age:
        return deepcopy(cached)
    try:
        stat = LIVE_SNAPSHOT_PATH.stat()
        if cached is not None and stat.st_mtime == _FILE_CACHE.get("mtime"):
            _FILE_CACHE["loaded_at"] = now
            return deepcopy(cached)
        data = json.loads(LIVE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        _FILE_CACHE.update({"mtime": stat.st_mtime, "loaded_at": now, "data": data})
        return deepcopy(data)
    except Exception:
        return {}


def _current_or_file():
    with _LOCK:
        current = deepcopy(_SNAPSHOT)
    if current.get("updated_at") or current.get("speeds") or current.get("summary"):
        return current
    return _load_file_snapshot()


def update_live_speeds(rows, updated_at=None):
    """Store current per-device live speeds in memory.

    Speeds are bytes/sec, matching live_device_speed. Readers convert to the
    units they need.
    """
    ts = updated_at or _now_text()
    speeds = {}
    for row in rows or []:
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        speeds[ip] = {
            "ip": ip,
            "mac": str(row.get("mac") or ""),
            "rx_bps": float(row.get("rx_bps") or 0),
            "tx_bps": float(row.get("tx_bps") or 0),
            "total_bps": float(row.get("total_bps") or 0),
            "updated_at": str(row.get("updated_at") or ts),
            "name": str(row.get("name") or ip),
        }
    with _LOCK:
        _SNAPSHOT["updated_at"] = ts
        _SNAPSHOT["speeds"] = speeds
        _write_file_locked()


def update_heartbeat(status, note="", updated_at=None):
    ts = updated_at or _now_text()
    with _LOCK:
        _SNAPSHOT["heartbeat"] = {
            "status": str(status or ""),
            "note": str(note or ""),
            "updated_at": ts,
        }
        if not _SNAPSHOT.get("updated_at"):
            _SNAPSHOT["updated_at"] = ts
        _write_file_locked()


def update_quality(row):
    with _LOCK:
        _SNAPSHOT["quality"] = dict(row or {})
        if row and row.get("ts"):
            _SNAPSHOT["updated_at"] = str(row.get("ts"))
        _write_file_locked()


def update_summary(values, updated_at=None):
    ts = updated_at or _now_text()
    with _LOCK:
        summary = dict(_SNAPSHOT.get("summary") or {})
        summary.update(dict(values or {}))
        summary["updated_at"] = ts
        _SNAPSHOT["summary"] = summary
        _SNAPSHOT["updated_at"] = ts
        _write_file_locked()


def speeds():
    return deepcopy((_current_or_file().get("speeds") or {}))


def network_speed():
    rows = speeds().values()
    rx = sum(float(row.get("rx_bps") or 0) for row in rows)
    tx = sum(float(row.get("tx_bps") or 0) for row in rows)
    return {
        "rx_bps": rx,
        "tx_bps": tx,
        "total_bps": rx + tx,
        "source": "memory",
    }


def heartbeat():
    return dict(_current_or_file().get("heartbeat") or {})


def quality():
    return dict(_current_or_file().get("quality") or {})


def summary():
    data = _current_or_file()
    result = dict(data.get("summary") or {})
    result["snapshot_age_seconds"] = _snapshot_age(data)
    result["generated_at"] = data.get("updated_at") or result.get("updated_at") or ""
    return result


def snapshot_age_seconds():
    return _snapshot_age(_current_or_file())


def clear():
    with _LOCK:
        _SNAPSHOT["updated_at"] = ""
        _SNAPSHOT["speeds"] = {}
        _SNAPSHOT["heartbeat"] = {}
        _SNAPSHOT["quality"] = {}
        _SNAPSHOT["summary"] = {}
        try:
            LIVE_SNAPSHOT_PATH.unlink(missing_ok=True)
        except Exception:
            pass
    _FILE_CACHE.update({"mtime": 0.0, "loaded_at": 0.0, "data": None})
