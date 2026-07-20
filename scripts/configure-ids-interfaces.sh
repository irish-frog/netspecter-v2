#!/usr/bin/env bash
set -euo pipefail

BRIDGE_NAME="${1:-br0}"
MODE="${2:-apply}"

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: required command '$command_name' was not found. Install it before configuring IDS capture interfaces." >&2
    exit 2
  fi
}

bridge_members() {
  local bridge_name="$1"
  bridge link show master "$bridge_name" 2>/dev/null |
    awk '
      /^[0-9]+:/ {
        name=$2
        sub(/:$/, "", name)
        sub(/@.*/, "", name)
        if (name != "") print name
      }
    ' |
    sort -u
}

set_offload() {
  local iface="$1"
  local feature="$2"
  local label="$3"

  echo "Disabling ${label} on ${iface}"
  if ! ethtool -K "$iface" "$feature" off >/dev/null 2>&1; then
    echo "WARNING: ${iface} does not support changing ${label}, or the setting is already fixed." >&2
  fi
}

show_settings() {
  local iface="$1"
  echo "Current offload settings for ${iface}:"
  ethtool -k "$iface" | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload):' || true
}

require_command bridge
require_command ethtool

echo "NetSpecter IDS bridge: ${BRIDGE_NAME}"
mapfile -t MEMBERS < <(bridge_members "$BRIDGE_NAME")

if [ "${#MEMBERS[@]}" -eq 0 ]; then
  echo "ERROR: no interfaces are currently attached to bridge '${BRIDGE_NAME}'." >&2
  exit 1
fi

echo "Detected bridge members: ${MEMBERS[*]}"

for iface in "${MEMBERS[@]}"; do
  if [ "$MODE" = "--verify" ] || [ "$MODE" = "verify" ]; then
    show_settings "$iface"
  else
    set_offload "$iface" gro "GRO"
    set_offload "$iface" gso "GSO"
    set_offload "$iface" tso "TSO"
    show_settings "$iface"
  fi
done
