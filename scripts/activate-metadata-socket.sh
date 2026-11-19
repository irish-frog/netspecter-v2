#!/usr/bin/env bash
# First migration: an already-running collector cannot receive a newly started socket.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo "Socket activation requires root." >&2; exit 1; }
if ! systemctl is-active --quiet netspecter-tls-metadata.socket; then
  echo "Preparing TLS socket activation: pausing NetSpecter collector/producers; AdGuard and bridge forwarding stay running."
  for unit in netspecter-watchdog.timer netspecter-watchdog.service netspecter-tls-inspector.service netspecter-softflowd.service netspecter-collector.service; do
    if [[ $(systemctl show "$unit" --property=LoadState --value) == loaded ]]; then
      systemctl stop "$unit"
    fi
  done
  systemctl reset-failed netspecter-tls-metadata.socket netspecter-collector.service
fi
systemctl enable --now netspecter-tls-metadata.socket
systemctl is-active --quiet netspecter-tls-metadata.socket
