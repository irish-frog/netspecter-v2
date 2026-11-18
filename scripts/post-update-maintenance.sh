#!/usr/bin/env bash
set -euo pipefail

echo "Running NetSpecter post-update maintenance..."

disable_suricata_safely() {
  timeout 20s systemctl stop suricata >/dev/null 2>&1 || true
  timeout 10s systemctl disable suricata >/dev/null 2>&1 || true
  systemctl kill suricata >/dev/null 2>&1 || true
  systemctl reset-failed suricata >/dev/null 2>&1 || true
}

install_db_maintenance_timer() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Skipping database maintenance timer install; root privileges are required." >&2
    return 0
  fi

  local root_dir
  root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
  if [ ! -f "$root_dir/systemd/netspecter-db-maintenance.service" ] || [ ! -f "$root_dir/systemd/netspecter-db-maintenance.timer" ]; then
    echo "WARNING: NetSpecter database maintenance unit files were not found." >&2
    return 0
  fi

  if [ -f "$root_dir/scripts/daily-db-maintenance.sh" ]; then
    chmod 755 "$root_dir/scripts/daily-db-maintenance.sh"
  fi
  cp "$root_dir/systemd/netspecter-db-maintenance.service" /etc/systemd/system/netspecter-db-maintenance.service
  cp "$root_dir/systemd/netspecter-db-maintenance.timer" /etc/systemd/system/netspecter-db-maintenance.timer
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now netspecter-db-maintenance.timer >/dev/null 2>&1 || true
  systemctl restart netspecter-db-maintenance.timer >/dev/null 2>&1 || true
}

install_ui_update_helper() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Skipping UI update helper install; root privileges are required." >&2
    return 0
  fi

  local root_dir
  root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
  if [ ! -f "$root_dir/systemd/netspecter-update.service" ] || [ ! -f "$root_dir/systemd/netspecter-update.path" ]; then
    echo "WARNING: NetSpecter UI update unit files were not found." >&2
    return 0
  fi

  if [ -f "$root_dir/scripts/run-ui-update.sh" ]; then
    chmod 755 "$root_dir/scripts/run-ui-update.sh"
  fi
  cp "$root_dir/systemd/netspecter-update.service" /etc/systemd/system/netspecter-update.service
  cp "$root_dir/systemd/netspecter-update.path" /etc/systemd/system/netspecter-update.path
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now netspecter-update.path >/dev/null 2>&1 || true
  systemctl restart netspecter-update.path >/dev/null 2>&1 || true
}

disable_suricata_safely
systemctl disable --now netspecter-nic-offload.service >/dev/null 2>&1 || true
install_db_maintenance_timer
install_ui_update_helper
echo "NetSpecter post-update maintenance complete; Suricata is disabled."
