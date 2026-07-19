#!/bin/bash
set -euo pipefail

echo "=== NetSpecter Full Appliance Installer ==="

INSTALL_DIR="/opt/netspecter"
CONFIG_DIR="/etc/netspecter"
DATA_DIR="/var/lib/netspecter"
SERVICE_DIR="/etc/systemd/system"
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
      if ! systemctl is-active --quiet suricata; then
        timeout 20s systemctl enable --now suricata >/dev/null 2>&1 || true
      fi
    elif suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1; then
      systemctl enable --now suricata || true
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
apt install -y python3 python3-pip python3-venv sqlite3 bridge-utils nftables tcpdump curl nano git bmon vnstat ieee-data snmp dnsutils cifs-utils openssl
install_speedtest_optional
install_suricata_optional

echo "[4/10] Creating folders..."
mkdir -p "$INSTALL_DIR/static" "$INSTALL_DIR/scripts" "$INSTALL_DIR/adguard" "$CONFIG_DIR/adguard" "$DATA_DIR"

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
  rm -rf "$INSTALL_DIR/netspecter_vault" "$INSTALL_DIR/services" "$INSTALL_DIR/config" "$INSTALL_DIR/docs" "$INSTALL_DIR/licenses"
  cp -r netspecter_vault "$INSTALL_DIR/netspecter_vault"
  cp -r services "$INSTALL_DIR/services"
  cp -r config "$INSTALL_DIR/config"
  cp -r static/. "$INSTALL_DIR/static/"
  cp -r scripts/. "$INSTALL_DIR/scripts/"
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
chown -R root:root "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
chmod 700 "$CONFIG_DIR" "$CONFIG_DIR/adguard" "$DATA_DIR"
chmod 600 "$CONFIG_DIR/config.json" "$CONFIG_DIR/netspecter-https.crt" "$CONFIG_DIR/netspecter-https.key" "$DATA_DIR/netspecter.db" "$DATA_DIR/netspecter_dns.db" "$DATA_DIR/netspecter_traffic.db" "$DATA_DIR/netspecter_security.db" "$DATA_DIR/cache.json" "$DATA_DIR/oui_cache.json"
chmod +x "$INSTALL_DIR/live_packet_collector.py"
chmod +x "$INSTALL_DIR/netspecter_https_proxy.py"
chmod +x "$INSTALL_DIR/scheduled_speedtest.py"
chmod +x "$INSTALL_DIR/monitor_sweeper.py"
chmod +x "$INSTALL_DIR/collector_watchdog.sh"
chmod +x "$INSTALL_DIR/scripts/render-adguard-template.sh"
chmod +x "$INSTALL_DIR/scripts/reset-history.sh"
chmod +x "$INSTALL_DIR/scripts/post-update-maintenance.sh"
chmod +x /usr/local/bin/netspecter-vault

echo "[8/10] Preparing AdGuard template..."
"$INSTALL_DIR/scripts/render-adguard-template.sh" "$INSTALL_DIR/adguard/AdGuardHome.yaml.example" "$CONFIG_DIR/adguard/AdGuardHome.yaml.generated" || true

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
systemctl daemon-reload
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

echo "[10/10] IDS setup complete."

echo ""
echo "=== NetSpecter installed ==="
echo "Open: https://SERVER-IP:9443"
echo "AdGuard template: $CONFIG_DIR/adguard/AdGuardHome.yaml.generated"
echo "Check: systemctl status netspecter-web netspecter-https netspecter-collector"
