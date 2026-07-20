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

[Service]
RestartSec=60
CPUQuota=50%
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
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
    out.extend(["", "af-packet:", f"  - interface: {iface}"])

path.write_text("\n".join(out) + "\n")
PY
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

install_safe_suricata_logrotate
install_suricata_safety_override
configure_suricata_interface
refresh_suricata_rules
systemctl reset-failed logrotate >/dev/null 2>&1 || true

echo "NetSpecter post-update maintenance complete."
