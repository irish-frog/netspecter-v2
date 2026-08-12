#!/usr/bin/env python3
import json
import os
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import netspecter_live_snapshot as live_snapshot


CONFIG_PATH = Path("/etc/netspecter/config.json")
DB_PATH = Path("/var/lib/netspecter/netspecter.db")
SLOTS = {
    1: [12],
    2: [8, 18],
    3: [7, 13, 19],
    4: [7, 11, 15, 19],
    5: [6, 10, 14, 18, 22],
}


def scheduled_runs():
    try:
        config = json.loads(CONFIG_PATH.read_text())
        return min(5, max(0, int(config.get("scheduled_speedtests_per_day", 0) or 0)))
    except Exception:
        return 0


def scheduled_frequency(config):
    frequency = str(config.get("scheduled_speedtest_frequency") or "").strip().lower()
    if frequency in {"daily", "weekly"}:
        return frequency
    return "daily" if int(config.get("scheduled_speedtests_per_day", 0) or 0) else "disabled"


def scheduled_time(config):
    text = str(config.get("scheduled_speedtest_time") or "12:00").strip()
    match = re.fullmatch(r"(\d{1,2}):(\d{2})", text)
    if not match:
        return (12, 0)
    hour = max(0, min(23, int(match.group(1))))
    minute = max(0, min(59, int(match.group(2))))
    return (hour, minute)


def load_config():
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception:
        return {}


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=30000")
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS speed_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            latency_ms REAL,
            download_mbps REAL,
            upload_mbps REAL,
            result_text TEXT,
            success INTEGER DEFAULT 0
        )
        """
    )
    con.commit()
    return con


def parse_value(pattern, output):
    match = re.search(pattern, output or "", re.IGNORECASE)
    return float(match.group(1)) if match else None


def speed_value_mbps(value):
    try:
        number = float(value)
    except Exception:
        return None
    return number / 1000000.0 if number > 10000 else number


def parse_metrics(output):
    try:
        payload = json.loads(output or "")
    except Exception:
        payload = None
    if isinstance(payload, dict):
        latency = payload.get("ping") or payload.get("latency")
        if isinstance(latency, dict):
            latency = latency.get("latency") or latency.get("value")
        download = payload.get("download")
        if isinstance(download, dict):
            if download.get("bandwidth") is not None:
                download = float(download.get("bandwidth")) * 8 / 1000000.0
            else:
                download = download.get("bytes") or download.get("value")
        upload = payload.get("upload")
        if isinstance(upload, dict):
            if upload.get("bandwidth") is not None:
                upload = float(upload.get("bandwidth")) * 8 / 1000000.0
            else:
                upload = upload.get("bytes") or upload.get("value")
        return (
            float(latency) if latency is not None else None,
            speed_value_mbps(download),
            speed_value_mbps(upload),
        )
    return (
        parse_value(r"(?:Latency|Ping):\s*([0-9.]+)\s*ms", output),
        parse_value(r"Download:\s*([0-9.]+)\s*(?:Mbit/s|Mbps)", output),
        parse_value(r"Upload:\s*([0-9.]+)\s*(?:Mbit/s|Mbps)", output),
    )


def speedtest_command(config):
    """Find speedtest-cli or Ookla speedtest for scheduled speed tests."""
    configured = str(config.get("speedtest_cli_path") or "").strip()
    server_id = str(config.get("speedtest_server_id") or "").strip()
    candidates = [configured] if configured else []
    candidates.extend(["speedtest-cli", "/usr/bin/speedtest-cli", "/usr/local/bin/speedtest-cli", "speedtest", "/usr/bin/speedtest"])
    resolved = ""
    for candidate in candidates:
        if not candidate:
            continue
        if "librespeed" in candidate.lower():
            continue
        path = shutil.which(candidate) if os.path.basename(candidate) == candidate else candidate
        if path and Path(path).exists():
            resolved = path
            break
    if not resolved:
        return None
    if os.path.basename(resolved) == "speedtest":
        command = [resolved, "--accept-license", "--accept-gdpr", "--format=json"]
        if server_id:
            command.extend(["--server-id", server_id])
        return command
    command = [resolved, "--json"]
    if server_id:
        command.extend(["--server", server_id])
    return command


def run_test():
    config = load_config()
    env = os.environ.copy()
    env.setdefault("HOME", "/root")
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("LC_ALL", "C.UTF-8")
    success = False
    try:
        command = speedtest_command(config)
        if command is None:
            raise FileNotFoundError("speedtest-cli not found")
        timeout = max(15, min(300, int(config.get("speedtest_timeout_seconds", 120) or 120)))
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            env=env,
        )
        output = (result.stdout or "").strip() or "Speed test returned no output."
        success = result.returncode == 0
        if not success:
            output = f"Speed test failed (exit {result.returncode}).\n{output}"
    except Exception as error:
        output = f"Scheduled speed test could not run: {error}"
    latency, download, upload = parse_metrics(output)
    return (output, latency, download, upload, success)


def main():
    config = load_config()
    runs = min(5, max(0, int(config.get("scheduled_speedtests_per_day", 0) or 0)))
    if runs == 0:
        return
    now = datetime.now()
    frequency = scheduled_frequency(config)
    if frequency == "disabled":
        return
    if runs == 1:
        hour, minute = scheduled_time(config)
        due = 1 if (now.hour, now.minute) >= (hour, minute) else 0
    else:
        due = sum(1 for hour in SLOTS[runs] if now.hour >= hour)
    if due == 0:
        return
    con = connect_db()
    try:
        if frequency == "weekly" and runs == 1:
            week_start = (now - timedelta(days=now.weekday())).strftime("%Y-%m-%d")
            next_week = (now - timedelta(days=now.weekday()) + timedelta(days=7)).strftime("%Y-%m-%d")
            completed = con.execute(
                """
                SELECT COUNT(*) FROM speed_tests
                WHERE source='scheduled'
                  AND substr(ts, 1, 10) >= ?
                  AND substr(ts, 1, 10) < ?
                """,
                (week_start, next_week),
            ).fetchone()[0]
        else:
            completed = con.execute(
                "SELECT COUNT(*) FROM speed_tests WHERE source='scheduled' AND substr(ts, 1, 10)=?",
                (now.strftime("%Y-%m-%d"),),
            ).fetchone()[0]
    finally:
        con.close()
    if completed >= due:
        return
    output, latency, download, upload, success = run_test()
    ts = now.strftime("%Y-%m-%d %H:%M:%S")
    con = connect_db()
    con.execute(
        """
        INSERT INTO speed_tests (ts, source, latency_ms, download_mbps, upload_mbps, result_text, success)
        VALUES (?, 'scheduled', ?, ?, ?, ?, ?)
        """,
        (ts, latency, download, upload, output, 1 if success else 0),
    )
    con.commit()
    con.close()
    live_snapshot.update_summary({
        "last_speed_test": {
            "completed_at": ts if success else None,
            "download_mbps": download,
            "upload_mbps": upload,
            "ping_ms": latency,
            "status": "completed" if success else "failed",
            "source": "scheduled",
        }
    }, ts)


if __name__ == "__main__":
    main()
