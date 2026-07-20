#!/usr/bin/env bash
set -euo pipefail

echo "Running NetSpecter post-update maintenance..."

disable_suricata_safely() {
  timeout 20s systemctl stop suricata >/dev/null 2>&1 || true
  timeout 10s systemctl disable suricata >/dev/null 2>&1 || true
  systemctl kill suricata >/dev/null 2>&1 || true
  systemctl reset-failed suricata >/dev/null 2>&1 || true
}

install_safe_suricata_logrotate() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Skipping Suricata logrotate maintenance; root privileges are required." >&2
    return 0
  fi

  mkdir -p /var/log/suricata
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
  if [ "$(id -u)" -ne 0 ]; then
    echo "Skipping Suricata systemd safety override; root privileges are required." >&2
    return 0
  fi

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
  systemctl daemon-reload >/dev/null 2>&1 || true
}

ensure_ethtool() {
  if command -v ethtool >/dev/null 2>&1; then
    return 0
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "Skipping ethtool installation; root privileges are required." >&2
    return 0
  fi
  echo "Installing ethtool for IDS bridge capture preparation..."
  apt install -y ethtool
}

install_nic_offload_service() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Skipping IDS NIC offload service maintenance; root privileges are required." >&2
    return 0
  fi

  local root_dir
  root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
  if [ -f "$root_dir/scripts/configure-ids-interfaces.sh" ]; then
    chmod 755 "$root_dir/scripts/configure-ids-interfaces.sh"
  else
    echo "WARNING: configure-ids-interfaces.sh was not found." >&2
    return 0
  fi
  if [ -f "$root_dir/systemd/netspecter-nic-offload.service" ]; then
    cp "$root_dir/systemd/netspecter-nic-offload.service" /etc/systemd/system/netspecter-nic-offload.service
  else
    echo "WARNING: netspecter-nic-offload.service was not found." >&2
    return 0
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable netspecter-nic-offload.service >/dev/null 2>&1 || true
  if "$root_dir/scripts/configure-ids-interfaces.sh" "$(detect_suricata_interface || echo br0)"; then
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

  local config_path="${NETSPECTER_CONFIG_ROOT:-/etc/netspecter}/config.json"
  if [ -r "$config_path" ]; then
    python3 - "$config_path" <<'PY'
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
  if [ "$(id -u)" -ne 0 ]; then
    echo "Skipping Suricata interface maintenance; root privileges are required." >&2
    return 0
  fi
  if [ ! -r /etc/suricata/suricata.yaml ]; then
    return 0
  fi

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

refresh_suricata_rules() {
  if ! command -v suricata >/dev/null 2>&1; then
    echo "Suricata is not installed; skipping IDS rule maintenance."
    return 0
  fi

  mkdir -p /var/lib/suricata/rules /var/log/suricata

  local rules_file="/var/lib/suricata/rules/suricata.rules"
  local refresh_rules=0
  if [ ! -s "$rules_file" ]; then
    refresh_rules=1
  elif [ "$(find "$rules_file" -mtime +14 -print -quit 2>/dev/null)" ]; then
    refresh_rules=1
  fi

  if [ "$refresh_rules" -eq 1 ] && command -v suricata-update >/dev/null 2>&1; then
    if ! suricata-update; then
      echo "WARNING: suricata-update failed; leaving existing IDS rules in place." >&2
    fi
  elif [ "$refresh_rules" -eq 1 ]; then
    echo "suricata-update is not installed; skipping IDS rule refresh."
  else
    echo "Suricata rules are present and less than 14 days old; skipping rule refresh."
  fi

  if [ "$refresh_rules" -eq 0 ]; then
    echo "Suricata rules are fresh; skipping validation restart."
    if suricata_interface_available && ! systemctl is-active --quiet suricata; then
      timeout 20s systemctl enable --now suricata >/dev/null 2>&1 || true
    fi
  elif suricata_interface_available && suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1; then
    systemctl reset-failed suricata >/dev/null 2>&1 || true
    timeout 20s systemctl restart suricata >/dev/null 2>&1 || true
  else
    echo "WARNING: Suricata configuration validation failed; not restarting Suricata." >&2
  fi
  guard_suricata_restart_loop
}

reclassify_ids_alerts() {
  local python_bin="${NETSPECTER_PYTHON:-/opt/netspecter/venv/bin/python}"
  if [ ! -x "$python_bin" ]; then
    python_bin="$(command -v python3 || true)"
  fi
  if [ -z "$python_bin" ]; then
    echo "Skipping IDS alert reclassification; Python is not available." >&2
    return 0
  fi

  "$python_bin" - <<'PY'
from netspecter_db import connect_db, init_db
from netspecter_ids import reclassify_default_ids_alerts

init_db()
changed = reclassify_default_ids_alerts(connect_db)
print(f"IDS alert severity reclassification complete ({changed} rows touched).")
PY
}

install_safe_suricata_logrotate
ensure_ethtool
install_suricata_safety_override
configure_suricata_interface
install_nic_offload_service
refresh_suricata_rules
reclassify_ids_alerts
systemctl reset-failed logrotate >/dev/null 2>&1 || true

echo "NetSpecter post-update maintenance complete."
