#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/netspecter}"
CONFIG_PATH="${NETSPECTER_CONFIG_PATH:-/etc/netspecter/config.json}"
DATA_DIR="${NETSPECTER_DATA_ROOT:-/var/lib/netspecter}"
DB_PATH="${NETSPECTER_DB_PATH:-$DATA_DIR/netspecter.db}"
SURICATA_LOG_DIR="${SURICATA_LOG_DIR:-/var/log/suricata}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

echo "Disabling NetSpecter security features in config: $CONFIG_PATH"
if [ -f "$CONFIG_PATH" ]; then
  as_root "$PYTHON_BIN" - "$CONFIG_PATH" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data.update({
    "security_features_enabled": False,
    "suricata_enabled": False,
    "ids_auto_ban_enabled": False,
    "ids_email_enabled": False,
    "ids_telegram_enabled": False,
    "threat_intel_enabled": False,
    "anomaly_enabled": False,
})
for key in ("ids_banned_ips", "ids_banned_domains", "ids_exceptions"):
    data[key] = []
path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
PY
else
  echo "Config file not found; skipping config update."
fi

echo "Stopping Suricata without uninstalling the package."
as_root systemctl stop suricata >/dev/null 2>&1 || true
as_root systemctl disable suricata >/dev/null 2>&1 || true
as_root systemctl reset-failed suricata >/dev/null 2>&1 || true

echo "Restarting NetSpecter collector/web services if present."
as_root systemctl restart netspecter-collector.service >/dev/null 2>&1 || true
as_root systemctl restart netspecter-web.service >/dev/null 2>&1 || true

echo "Clearing NetSpecter IDS, threat intelligence, anomaly, and security incident data: $DB_PATH"
if [ -f "$DB_PATH" ]; then
  as_root "$PYTHON_BIN" - "$DB_PATH" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
tables = [
    "ids_events",
    "ids_eve_state",
    "ids_alert_notifications",
    "threat_indicators",
    "threat_feed_state",
    "threat_correlations",
    "anomaly_device_daily",
    "anomaly_device_hourly",
    "anomaly_events",
    "anomaly_expected_events",
    "security_incidents",
    "security_incident_events",
    "security_incident_notes",
    "security_incident_audit",
]
checkpoint_names = [
    "threat_intel_ids_events",
    "anomaly_ids_events",
    "incident_builder_last_processed_id",
    "incident_builder_ids_events",
    "suricata_metadata",
]
con = sqlite3.connect(db_path)
try:
    con.execute("PRAGMA busy_timeout=5000")
    existing = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in tables:
        if table in existing:
            con.execute(f"DELETE FROM {table}")
    if "processing_checkpoints" in existing:
        con.executemany("DELETE FROM processing_checkpoints WHERE name=?", [(name,) for name in checkpoint_names])
    con.commit()
    con.execute("VACUUM")
finally:
    con.close()
PY
else
  echo "Database not found; skipping database cleanup."
fi

echo "Clearing Suricata logs: $SURICATA_LOG_DIR"
if [ -d "$SURICATA_LOG_DIR" ]; then
  as_root find "$SURICATA_LOG_DIR" -type f \( -name 'eve.json*' -o -name 'fast.log*' -o -name '*.log*' -o -name '*.json*' \) -delete
  as_root install -d -m 0755 "$SURICATA_LOG_DIR"
  as_root touch "$SURICATA_LOG_DIR/eve.json" "$SURICATA_LOG_DIR/fast.log"
  as_root chmod 0640 "$SURICATA_LOG_DIR/eve.json" "$SURICATA_LOG_DIR/fast.log" || true
else
  echo "Suricata log directory not found; skipping log cleanup."
fi

echo "Security features are disabled; Suricata remains installed."
