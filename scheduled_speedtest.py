#!/usr/bin/env python3
import json
import os
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime
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
            download = download.get("bandwidth") or download.get("bytes") or download.get("value")
        upload = payload.get("upload")
        if isinstance(upload, dict):
            upload = upload.get("bandwidth") or upload.get("bytes") or upload.get("value")
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


def librespeed_command(config):
    path = str(config.get("librespeed_cli_path") or "librespeed-cli").strip() or "librespeed-cli"
    resolved = path if Path(path).exists() else shutil.which(path)
    if not resolved:
        return None
    command = [resolved, "--json"]
    server_id = str(config.get("librespeed_server_id") or "").strip()
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
        command = librespeed_command(config)
        if command is None:
            raise FileNotFoundError("librespeed-cli not found")
        timeout = max(15, min(300, int(config.get("librespeed_timeout_seconds", 120) or 120)))
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
        output = f"Scheduled LibreSpeed test could not run: {error}"
    latency, download, upload = parse_metrics(output)
    return (output, latency, download, upload, success)


def main():
    runs = scheduled_runs()
    if runs == 0:
        return
    now = datetime.now()
    due = sum(1 for hour in SLOTS[runs] if now.hour >= hour)
    if due == 0:
        return
    con = connect_db()
    try:
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
