#!/bin/bash
set -euo pipefail

echo "=== NetSpecter Full Appliance Installer ==="

INSTALL_DIR="/opt/netspecter"
CONFIG_DIR="/etc/netspecter"
DATA_DIR="/var/lib/netspecter"
LOG_DIR="/var/log/netspecter"
SERVICE_DIR="/etc/systemd/system"
RUNTIME_USER="netspecter"
RUNTIME_GROUP="netspecter"
SOURCE_DIR="$(pwd -P)"
INSTALL_ADGUARD="${INSTALL_ADGUARD:-1}"
INSTALL_GATUS="${INSTALL_GATUS:-1}"
INSTALL_BESZEL="${INSTALL_BESZEL:-1}"
ADGUARD_JUST_INSTALLED=0
OS_ID=""
OS_VERSION_ID=""
OS_VERSION_CODENAME=""

if [ "${EUID}" -ne 0 ]; then
  echo "Please run as root." >&2
  exit 1
fi

detect_os() {
  if [ ! -r /etc/os-release ]; then
    echo "Cannot detect operating system: /etc/os-release not found." >&2
    exit 1
  fi

  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
  OS_VERSION_CODENAME="${VERSION_CODENAME:-}"

  if [ "$OS_ID" != "debian" ]; then
    echo "Unsupported operating system: ${PRETTY_NAME:-unknown}. NetSpecter v2 targets Debian 13 Trixie." >&2
    exit 1
  fi

  case "$OS_VERSION_ID" in
    13)
      echo "Detected Debian 13 Trixie."
      ;;
    12)
      echo "Detected Debian 12 Bookworm. Debian 13 Trixie is the primary supported OS; continuing without cross-release repositories."
      ;;
    *)
      echo "Unsupported Debian version: ${OS_VERSION_ID:-unknown}. NetSpecter v2 targets Debian 13 Trixie." >&2
      exit 1
      ;;
  esac
}

port_3000_in_use() {
  ss -H -ltn 'sport = :3000' 2>/dev/null | grep -q LISTEN
}

disable_suricata_safely() {
  timeout 20s systemctl stop suricata >/dev/null 2>&1 || true
  timeout 10s systemctl disable suricata >/dev/null 2>&1 || true
  systemctl kill suricata >/dev/null 2>&1 || true
  systemctl reset-failed suricata >/dev/null 2>&1 || true
}

install_speedtest_optional() {
  if dpkg-query -W -f='${Status}' speedtest 2>/dev/null | grep -q "install ok installed" || \
     dpkg-query -W -f='${Status}' speedtest-cli 2>/dev/null | grep -q "install ok installed"; then
    return 0
  fi

  echo "Installing Ookla Speedtest if the external repository supports this Debian release..."
  if curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash; then
    apt update || true
    if apt install -y speedtest; then
      return 0
    fi
  fi

  echo "Ookla Speedtest is unavailable for this Debian release; installing Debian speedtest-cli fallback..."
  if apt install -y speedtest-cli; then
    return 0
  fi

  echo "WARNING: no speed test client is available. NetSpecter will install without speed test support." >&2
  return 0
}

install_suricata_optional() {
  if apt install -y suricata suricata-update; then
    mkdir -p /var/lib/suricata/rules /var/log/suricata
    install_suricata_safety_override
    configure_suricata_interface
    SURICATA_RULES_FILE="/var/lib/suricata/rules/suricata.rules"
    SURICATA_REFRESH_RULES=0
    if [ ! -s "$SURICATA_RULES_FILE" ]; then
      SURICATA_REFRESH_RULES=1
    elif [ "$(find "$SURICATA_RULES_FILE" -mtime +14 -print -quit 2>/dev/null)" ]; then
      SURICATA_REFRESH_RULES=1
    fi
    if [ "$SURICATA_REFRESH_RULES" -eq 1 ]; then
      if ! suricata-update; then
        echo "WARNING: Suricata rule update failed; IDS may have no active rules until suricata-update succeeds." >&2
      fi
    else
      echo "Suricata rules are present and less than 14 days old; skipping rule refresh."
    fi
    if [ "$SURICATA_REFRESH_RULES" -eq 0 ]; then
      echo "Suricata rules are fresh; skipping validation restart."
      if suricata_interface_available && ! systemctl is-active --quiet suricata; then
        timeout 20s systemctl enable --now suricata >/dev/null 2>&1 || true
      fi
    elif suricata_interface_available && suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1; then
      timeout 20s systemctl enable --now suricata >/dev/null 2>&1 || true
      guard_suricata_restart_loop
    else
      echo "WARNING: Suricata installed but configuration validation failed; not restarting Suricata." >&2
    fi
  else
    echo "WARNING: Suricata could not be installed from Debian ${OS_VERSION_CODENAME:-$OS_VERSION_ID} repositories. IDS views will stay available but may have no alert log." >&2
  fi

  mkdir -p /var/log/suricata
  if getent group adm >/dev/null 2>&1; then
    chgrp adm /var/log/suricata 2>/dev/null || true
    chmod 750 /var/log/suricata 2>/dev/null || true
  fi

  cat >/etc/logrotate.d/suricata <<'EOF'
/var/log/suricata/*.log
/var/log/suricata/*.json
{
        rotate 14
        missingok
        compress
        copytruncate
        sharedscripts
        postrotate
                if [ -s /var/run/suricata.pid ]; then
                        /bin/kill -HUP "$(cat /var/run/suricata.pid)" 2>/dev/null || true
                fi
        endscript
}
EOF
}

install_suricata_safety_override() {
  mkdir -p /etc/systemd/system/suricata.service.d
  cat >/etc/systemd/system/suricata.service.d/netspecter-safety.conf <<'EOF'
[Unit]
StartLimitIntervalSec=10min
StartLimitBurst=3
Wants=netspecter-nic-offload.service
After=netspecter-nic-offload.service

[Service]
RestartSec=60
CPUQuota=50%
EOF
  systemctl daemon-reload
}

install_nic_offload_service() {
  if [ ! -f "$INSTALL_DIR/scripts/configure-ids-interfaces.sh" ]; then
    echo "WARNING: IDS interface preparation script is not installed yet." >&2
    return 0
  fi
  chmod 755 "$INSTALL_DIR/scripts/configure-ids-interfaces.sh"
  if [ -f systemd/netspecter-nic-offload.service ]; then
    cp systemd/netspecter-nic-offload.service "$SERVICE_DIR/netspecter-nic-offload.service"
  elif [ -f "$INSTALL_DIR/systemd/netspecter-nic-offload.service" ]; then
    cp "$INSTALL_DIR/systemd/netspecter-nic-offload.service" "$SERVICE_DIR/netspecter-nic-offload.service"
  else
    echo "WARNING: netspecter-nic-offload.service was not found; bridge offload settings will not be applied at boot." >&2
    return 0
  fi
  systemctl daemon-reload
  systemctl enable netspecter-nic-offload.service >/dev/null 2>&1 || true
  if "$INSTALL_DIR/scripts/configure-ids-interfaces.sh" "$(detect_suricata_interface || echo br0)"; then
    systemctl restart netspecter-nic-offload.service >/dev/null 2>&1 || true
  else
    echo "WARNING: IDS bridge members are not available yet; netspecter-nic-offload.service will retry at boot." >&2
  fi
}

detect_suricata_interface() {
  if [ -n "${NETSPECTER_SURICATA_IFACE:-}" ]; then
    echo "$NETSPECTER_SURICATA_IFACE"
    return 0
  fi

  if [ -r "$CONFIG_DIR/config.json" ]; then
    python3 - "$CONFIG_DIR/config.json" <<'PY'
import json
import sys
from pathlib import Path

try:
    data = json.loads(Path(sys.argv[1]).read_text())
    iface = str(data.get("packet_iface") or "").strip()
    if iface:
        print(iface)
except Exception:
    pass
PY
    return 0
  fi

  if ip link show br0 >/dev/null 2>&1; then
    echo "br0"
    return 0
  fi

  ip route show default 2>/dev/null | awk '/ default / {for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
}

configure_suricata_interface() {
  local iface
  iface="$(detect_suricata_interface)"
  iface="${iface:-br0}"
  echo "Configuring Suricata AF_PACKET interface: $iface"
  cp -a /etc/suricata/suricata.yaml "/etc/suricata/suricata.yaml.netspecter.bak.$(date +%Y%m%d%H%M%S)"

  python3 - "/etc/suricata/suricata.yaml" "$iface" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
iface = sys.argv[2]
lines = path.read_text().splitlines()
out = []
in_af_packet = False
changed = False

for line in lines:
    if re.match(r"^af-packet:\s*$", line):
        in_af_packet = True
        out.append(line)
        continue
    if in_af_packet and line and not line.startswith((" ", "\t", "-")):
        in_af_packet = False
    if in_af_packet and re.match(r"^\s*-\s*interface:\s*", line):
        indent = line[:len(line) - len(line.lstrip())]
        out.append(f"{indent}- interface: {iface}")
        changed = True
        continue
    out.append(line)

if not changed:
    out.extend(["", "af-packet:", f"  - interface: {iface}", "    cluster-id: 99", "    cluster-type: cluster_flow", "    defrag: yes", "    use-mmap: yes"])

path.write_text("\n".join(out) + "\n")
PY

  if command -v suricata >/dev/null 2>&1 && ! suricata -T -c /etc/suricata/suricata.yaml; then
    local backup
    backup="$(ls -1t /etc/suricata/suricata.yaml.netspecter.bak.* 2>/dev/null | head -n 1 || true)"
    if [ -n "$backup" ]; then
      cp -a "$backup" /etc/suricata/suricata.yaml
    fi
    echo "ERROR: Suricata configuration validation failed; restored previous configuration." >&2
    return 1
  fi
}

suricata_interface_available() {
  local iface
  iface="$(detect_suricata_interface)"
  iface="${iface:-br0}"
  if ip link show "$iface" >/dev/null 2>&1; then
    return 0
  fi
  echo "WARNING: Suricata interface '$iface' does not exist. Disabling Suricata until the capture interface is corrected." >&2
  disable_suricata_safely
  return 1
}

guard_suricata_restart_loop() {
  if ! systemctl list-unit-files suricata.service >/dev/null 2>&1; then
    return 0
  fi

  local restarts
  restarts="$(systemctl show suricata -p NRestarts --value 2>/dev/null || echo 0)"
  restarts="${restarts:-0}"
  if [ "$restarts" -ge 5 ]; then
    echo "WARNING: Suricata restart loop detected ($restarts restarts). Disabling Suricata to protect appliance CPU." >&2
    disable_suricata_safely
  fi
}

set_config_value() {
  local key="$1"
  local value="$2"
  python3 - "$CONFIG_DIR/config.json" "$key" "$value" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
data = {}
if path.exists():
    try:
        data = json.loads(path.read_text())
    except Exception:
        data = {}
data[key] = value
path.write_text(json.dumps(data, indent=2) + "\n")
PY
}

install_gatus_optional() {
  if [ "$INSTALL_GATUS" != "1" ]; then
    echo "Gatus install skipped. Run with INSTALL_GATUS=1 to install it."
    return 0
  fi

  echo "Installing Gatus status dashboard..."
  apt install -y golang-go

  if ! command -v gatus >/dev/null 2>&1; then
    GOBIN=/usr/local/bin go install github.com/TwiN/gatus/v5@latest
    go clean -cache -modcache || true
  fi

  mkdir -p "$CONFIG_DIR/gatus"
  cat > "$CONFIG_DIR/gatus/config.yaml" <<'EOF'
ui:
  title: NetSpecter Monitor
web:
  address: 127.0.0.1
  port: 18080
endpoints:
  - name: NetSpecter Health
    group: NetSpecter
    url: "http://127.0.0.1:5050/api/health/web"
    interval: 60s
    conditions:
      - "[STATUS] == 200"
  - name: Traffic Collector
    group: NetSpecter
    url: "http://127.0.0.1:5050/api/health/collector"
    interval: 60s
    conditions:
      - "[STATUS] == 200"
  - name: Bridge Interface
    group: NetSpecter
    url: "http://127.0.0.1:5050/api/health/bridge"
    interval: 60s
    conditions:
      - "[STATUS] == 200"
  - name: History Database
    group: NetSpecter
    url: "http://127.0.0.1:5050/api/health/database"
    interval: 60s
    conditions:
      - "[STATUS] == 200"
  - name: Service Watch
    group: NetSpecter
    url: "http://127.0.0.1:18080"
    interval: 60s
    conditions:
      - "[STATUS] == 200"
  - name: Metrics Engine
    group: NetSpecter
    url: "http://127.0.0.1:8090"
    interval: 60s
    conditions:
      - "[STATUS] == 200"
EOF

  chmod 700 "$CONFIG_DIR/gatus"
  chmod 600 "$CONFIG_DIR/gatus/config.yaml"
  cp systemd/gatus.service "$SERVICE_DIR/gatus.service"
  systemctl daemon-reload
  systemctl enable --now gatus

  set_config_value "gatus_url" "http://127.0.0.1:18080"
}

install_beszel_optional() {
  if [ "$INSTALL_BESZEL" != "1" ]; then
    echo "Beszel install skipped. Run with INSTALL_BESZEL=1 to install it."
    return 0
  fi

  if [ -x /opt/beszel/beszel ] && systemctl list-unit-files beszel-hub.service >/dev/null 2>&1; then
    echo "Beszel hub already installed; skipping reinstall."
    mkdir -p "$SERVICE_DIR/beszel-hub.service.d"
    cat > "$SERVICE_DIR/beszel-hub.service.d/netspecter-localhost.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/opt/beszel/beszel serve --http 127.0.0.1:8090
EOF
    systemctl daemon-reload
    systemctl enable --now beszel-hub || true
    systemctl restart beszel-hub || true
    set_config_value "beszel_url" "http://127.0.0.1:8090"
    return 0
  fi

  echo "Installing Beszel hub..."
  if curl -fsSL https://raw.githubusercontent.com/henrygd/beszel/main/supplemental/scripts/install-hub.sh | sh -s -- -p 8090; then
    mkdir -p "$SERVICE_DIR/beszel-hub.service.d"
    cat > "$SERVICE_DIR/beszel-hub.service.d/netspecter-localhost.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/opt/beszel/beszel serve --http 127.0.0.1:8090
EOF
    systemctl daemon-reload
    systemctl restart beszel-hub || true
    set_config_value "beszel_url" "http://127.0.0.1:8090"
  else
    echo "WARNING: Beszel hub could not be installed. NetSpecter will continue without Beszel health." >&2
  fi
}

ensure_runtime_user() {
  if ! getent group "$RUNTIME_GROUP" >/dev/null 2>&1; then
    groupadd --system "$RUNTIME_GROUP"
  fi
  if ! id -u "$RUNTIME_USER" >/dev/null 2>&1; then
    useradd --system --gid "$RUNTIME_GROUP" --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$RUNTIME_USER"
  fi
  if getent group adm >/dev/null 2>&1; then
    usermod -aG adm "$RUNTIME_USER"
  fi
}

apply_runtime_permissions() {
  chown -R root:root "$INSTALL_DIR"
  chown -R root:"$RUNTIME_GROUP" "$CONFIG_DIR"
  chown -R "$RUNTIME_USER":"$RUNTIME_GROUP" "$DATA_DIR" "$LOG_DIR"

  chmod 755 "$INSTALL_DIR"
  chmod 750 "$CONFIG_DIR" "$CONFIG_DIR/adguard" "$DATA_DIR" "$LOG_DIR"
  chmod 640 "$CONFIG_DIR/config.json" "$CONFIG_DIR/netspecter-https.crt" "$CONFIG_DIR/netspecter-https.key"
  chmod 660 "$DATA_DIR/netspecter.db" "$DATA_DIR/netspecter_dns.db" "$DATA_DIR/netspecter_traffic.db" "$DATA_DIR/netspecter_security.db" "$DATA_DIR/cache.json" "$DATA_DIR/oui_cache.json"

  find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
  find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
  if [ -d "$INSTALL_DIR/venv/bin" ]; then
    find "$INSTALL_DIR/venv/bin" -maxdepth 1 -type f -exec chmod 755 {} \;
  fi
  chmod +x "$INSTALL_DIR/live_packet_collector.py"
  chmod +x "$INSTALL_DIR/netspecter_https_proxy.py"
  chmod +x "$INSTALL_DIR/scheduled_speedtest.py"
  chmod +x "$INSTALL_DIR/monitor_sweeper.py"
  chmod +x "$INSTALL_DIR/collector_watchdog.sh"
  chmod +x "$INSTALL_DIR/scripts/render-adguard-template.sh"
  chmod +x "$INSTALL_DIR/scripts/reset-history.sh"
  chmod +x "$INSTALL_DIR/scripts/post-update-maintenance.sh"
  chmod +x /usr/local/bin/netspecter-vault
}

validate_anomaly_permissions() {
  local unit="${1:-netspecter-collector.service}"
  local unit_user
  local unit_group
  unit_user="$(systemctl show "$unit" -p User --value 2>/dev/null || true)"
  unit_group="$(systemctl show "$unit" -p Group --value 2>/dev/null || true)"
  unit_user="${unit_user:-root}"
  unit_group="${unit_group:-root}"

  echo "Anomaly service unit:   $unit"
  echo "Anomaly service user:   $unit_user"
  echo "Anomaly service group:  $unit_group"
  echo "Anomaly data store:     $DATA_DIR/netspecter.db"
  echo "Baseline state:         anomaly_device_daily and anomaly_device_hourly tables in netspecter.db"
  echo "Model/state files:      none; explainable baseline state is stored in SQLite"
  echo "Cache files:            $DATA_DIR/cache.json"
  echo "Lock files:             SQLite WAL/SHM/JOURNAL files in $DATA_DIR"
  echo "Export files:           generated on demand; no anomaly-specific export directory"
  echo "Anomaly logs:           journalctl -u $unit"
  echo "Scheduled anomaly unit: none; anomaly learning/detection runs inside netspecter-collector.service"

  runuser -u "$unit_user" -- test -r "$DATA_DIR/netspecter.db"
  runuser -u "$unit_user" -- test -w "$DATA_DIR/netspecter.db"
  runuser -u "$unit_user" -- test -w "$DATA_DIR"
  runuser -u "$unit_user" -- test -r "$DATA_DIR/cache.json"
  runuser -u "$unit_user" -- test -w "$DATA_DIR/cache.json"

  runuser -u "$unit_user" -- "$INSTALL_DIR/venv/bin/python" - "$DATA_DIR/netspecter.db" <<'PY'
import sqlite3
import sys
from pathlib import Path

db = Path(sys.argv[1])
conn = sqlite3.connect(db)
conn.execute("PRAGMA journal_mode=WAL")
conn.execute(
    "CREATE TABLE IF NOT EXISTS installer_anomaly_permission_test "
    "(id INTEGER PRIMARY KEY, value TEXT)"
)
conn.execute(
    "INSERT INTO installer_anomaly_permission_test(value) VALUES (?)",
    ("ok",)
)
conn.commit()
row = conn.execute(
    "SELECT value FROM installer_anomaly_permission_test ORDER BY id DESC LIMIT 1"
).fetchone()
if not row or row[0] != "ok":
    raise SystemExit("Anomaly database write/read validation failed")
conn.execute("DROP TABLE installer_anomaly_permission_test")
conn.commit()
conn.close()
print("Anomaly database permissions valid")
PY

  runuser -u "$unit_user" -- "$INSTALL_DIR/venv/bin/python" - "$DATA_DIR" <<'PY'
import os
import sys
from pathlib import Path

data_dir = Path(sys.argv[1])
path = data_dir / ".installer_anomaly_state_test"
path.write_text("ok\n")
if path.read_text() != "ok\n":
    raise SystemExit("Anomaly baseline/cache state write/read validation failed")
path.unlink()
print("Anomaly baseline/cache state permissions valid")
PY
}

detect_os

echo "[1/9] Refreshing package metadata and installing setup tools..."
apt update
apt install -y wget curl gnupg ca-certificates lsb-release iproute2

echo "[2/9] Installing AdGuard Home first if requested..."
if [ "$INSTALL_ADGUARD" = "1" ] && ! command -v AdGuardHome >/dev/null 2>&1 && [ ! -x /opt/AdGuardHome/AdGuardHome ]; then
  if port_3000_in_use; then
    echo "Port 3000 is already in use. Free it before installing AdGuard Home." >&2
    ss -ltnp 'sport = :3000' || true
    exit 1
  fi
  echo "AdGuard Home is separate third-party software licensed under GPL-3.0."
  echo "Project and source: https://github.com/AdguardTeam/AdGuardHome"
  echo "Licence: https://github.com/AdguardTeam/AdGuardHome/blob/master/LICENSE.txt"
  echo "NetSpecter third-party notices: $SOURCE_DIR/THIRD_PARTY_NOTICES.md"
  wget -O - https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
  ADGUARD_JUST_INSTALLED=1
else
  echo "AdGuard Home install skipped or already present."
fi

if [ "$ADGUARD_JUST_INSTALLED" = "1" ] && port_3000_in_use; then
  echo ""
  echo "=== AdGuard Home setup available ==="
  echo "After installation completes, open: http://SERVER-IP:3000"
  echo "In the AdGuard wizard, set its web/admin port to 80."
  echo "Continuing with NetSpecter installation now."
fi

echo "[3/10] Installing NetSpecter base packages..."
apt install -y python3 python3-pip python3-venv sqlite3 bridge-utils nftables tcpdump curl nano git bmon vnstat ieee-data snmp dnsutils cifs-utils openssl ethtool
install_speedtest_optional
install_suricata_optional
ensure_runtime_user

echo "[4/10] Creating folders..."
mkdir -p "$INSTALL_DIR/static" "$INSTALL_DIR/scripts" "$INSTALL_DIR/adguard" "$CONFIG_DIR/adguard" "$DATA_DIR" "$LOG_DIR"

echo "[5/10] Copying NetSpecter files..."
# A collector started outside systemd, or from an older build without locking,
# can otherwise keep writing stale totals after an upgrade.
systemctl stop netspecter-collector netspecter-live >/dev/null 2>&1 || true
systemctl disable netspecter-live >/dev/null 2>&1 || true
rm -f "$SERVICE_DIR/netspecter-live.service"
systemctl daemon-reload
pkill -f 'live_packet_collector.py' >/dev/null 2>&1 || true
if [ "$SOURCE_DIR" != "$(readlink -f "$INSTALL_DIR")" ]; then
  cp app.py "$INSTALL_DIR/app.py"
  cp netspecter_config.py "$INSTALL_DIR/netspecter_config.py"
  cp netspecter_db.py "$INSTALL_DIR/netspecter_db.py"
  cp netspecter_paths.py "$INSTALL_DIR/netspecter_paths.py"
  cp netspecter_ui_helpers.py "$INSTALL_DIR/netspecter_ui_helpers.py"
  cp netspecter_https_proxy.py "$INSTALL_DIR/netspecter_https_proxy.py"
  cp gunicorn_config.py "$INSTALL_DIR/gunicorn_config.py"
  cp wsgi.py "$INSTALL_DIR/wsgi.py"
  cp live_packet_collector.py "$INSTALL_DIR/live_packet_collector.py"
  cp scheduled_speedtest.py "$INSTALL_DIR/scheduled_speedtest.py"
  cp monitor_sweeper.py "$INSTALL_DIR/monitor_sweeper.py"
  cp collector_watchdog.sh "$INSTALL_DIR/collector_watchdog.sh"
  rm -rf "$INSTALL_DIR/netspecter_vault" "$INSTALL_DIR/services" "$INSTALL_DIR/config" "$INSTALL_DIR/docs" "$INSTALL_DIR/licenses" "$INSTALL_DIR/systemd"
  cp -r netspecter_vault "$INSTALL_DIR/netspecter_vault"
  cp -r services "$INSTALL_DIR/services"
  cp -r config "$INSTALL_DIR/config"
  cp -r static/. "$INSTALL_DIR/static/"
  cp -r scripts/. "$INSTALL_DIR/scripts/"
  cp -r systemd "$INSTALL_DIR/systemd"
  cp -r adguard/. "$INSTALL_DIR/adguard/"
  cp -r docs "$INSTALL_DIR/docs"
  cp -r licenses "$INSTALL_DIR/licenses"
  cp THIRD_PARTY_NOTICES.md "$INSTALL_DIR/THIRD_PARTY_NOTICES.md"
  cp LICENSE "$INSTALL_DIR/LICENSE"
  cp EULA.md "$INSTALL_DIR/EULA.md"
  cp README.md "$INSTALL_DIR/README.md"
else
  echo "Source is already $INSTALL_DIR; using files in place."
fi
cp netspecter-vault /usr/local/bin/netspecter-vault
if [ ! -f "$CONFIG_DIR/config.json" ]; then
  cp config.example.json "$CONFIG_DIR/config.json"
else
  echo "Existing config preserved: $CONFIG_DIR/config.json"
fi
[ -f cache.json ] && cp cache.json "$DATA_DIR/cache.json" || echo "{}" > "$DATA_DIR/cache.json"
[ -f oui_cache.json ] && cp oui_cache.json "$DATA_DIR/oui_cache.json" || echo "{}" > "$DATA_DIR/oui_cache.json"

echo "[6/10] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

echo "[7/10] Preparing database and permissions..."
touch "$DATA_DIR/netspecter.db" "$DATA_DIR/netspecter_dns.db" "$DATA_DIR/netspecter_traffic.db" "$DATA_DIR/netspecter_security.db"
if [ ! -s "$CONFIG_DIR/netspecter-https.crt" ] || [ ! -s "$CONFIG_DIR/netspecter-https.key" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout "$CONFIG_DIR/netspecter-https.key" \
      -out "$CONFIG_DIR/netspecter-https.crt" \
      -subj "/CN=NetSpecter" >/dev/null 2>&1
  else
    echo "OpenSSL is required to create the NetSpecter HTTPS certificate." >&2
    exit 1
  fi
fi
apply_runtime_permissions

echo "[8/10] Preparing AdGuard template..."
"$INSTALL_DIR/scripts/render-adguard-template.sh" "$INSTALL_DIR/adguard/AdGuardHome.yaml.example" "$CONFIG_DIR/adguard/AdGuardHome.yaml.generated" || true
apply_runtime_permissions

echo "[9/10] Installing systemd services..."
cp systemd/netspecter-web.service "$SERVICE_DIR/netspecter-web.service"
cp systemd/netspecter-https.service "$SERVICE_DIR/netspecter-https.service"
cp systemd/netspecter-collector.service "$SERVICE_DIR/netspecter-collector.service"
cp systemd/netspecter-watchdog.service "$SERVICE_DIR/netspecter-watchdog.service"
cp systemd/netspecter-watchdog.timer "$SERVICE_DIR/netspecter-watchdog.timer"
cp systemd/netspecter-speedtest.service "$SERVICE_DIR/netspecter-speedtest.service"
cp systemd/netspecter-speedtest.timer "$SERVICE_DIR/netspecter-speedtest.timer"
cp systemd/netspecter-monitor.service "$SERVICE_DIR/netspecter-monitor.service"
cp systemd/netspecter-monitor.timer "$SERVICE_DIR/netspecter-monitor.timer"
cp systemd/netspecter-vault.service "$SERVICE_DIR/netspecter-vault.service"
cp systemd/netspecter-vault.timer "$SERVICE_DIR/netspecter-vault.timer"
cp systemd/netspecter-nic-offload.service "$SERVICE_DIR/netspecter-nic-offload.service"
systemctl daemon-reload
install_nic_offload_service
validate_anomaly_permissions "netspecter-collector.service"
systemctl enable --now netspecter-web netspecter-https netspecter-collector netspecter-watchdog.timer netspecter-speedtest.timer netspecter-monitor.timer netspecter-vault.timer
systemctl restart netspecter-web netspecter-https netspecter-collector
systemctl restart netspecter-watchdog.timer
systemctl restart netspecter-speedtest.timer
systemctl restart netspecter-monitor.timer
systemctl restart netspecter-vault.timer
systemctl enable --now vnstat || true
systemctl enable AdGuardHome || true
install_gatus_optional
install_beszel_optional
"$INSTALL_DIR/scripts/post-update-maintenance.sh" || true
apply_runtime_permissions

echo "[10/10] IDS setup complete."

echo ""
echo "=== NetSpecter installed ==="
echo "Anomaly engine:        AVAILABLE (learning/detection runs inside netspecter-collector.service)"
echo "Anomaly database:      READ/WRITE OK"
echo "Baseline state:        READ/WRITE OK"
echo "Anomaly permissions:   VALID"
echo "Open: https://SERVER-IP:9443"
echo "AdGuard template: $CONFIG_DIR/adguard/AdGuardHome.yaml.generated"
echo "Check: systemctl status netspecter-web netspecter-https netspecter-collector"
