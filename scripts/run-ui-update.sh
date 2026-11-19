#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${NETSPECTER_INSTALL_ROOT:-/opt/netspecter}"
DATA_DIR="${NETSPECTER_DATA_ROOT:-/var/lib/netspecter}"
LOG_FILE="${DATA_DIR}/update.log"
STATE_FILE="${DATA_DIR}/update_state"
REQUEST_FILE="${DATA_DIR}/update.request"

mkdir -p "$DATA_DIR"
rm -f "$REQUEST_FILE"

{
  printf '\n=== NetSpecter UI update started %s ===\n' "$(date)"
  printf 'running %s\n' "$(date +%s)" > "$STATE_FILE"
  # Serialize with UI maintenance and manual resets. /run is root-owned.
  [[ ! -L /run/netspecter-operation.lock ]] || { echo "Unsafe operation lock"; exit 1; }
  exec 9>/run/netspecter-operation.lock
  if ! flock -n 9; then
    echo "Another maintenance operation is running; update refused."
    printf 'failed %s\n' "$(date +%s)" > "$STATE_FILE"
    exit 1
  fi
  [[ ! -e "$DATA_DIR/history-reset.in-progress" ]] || { echo "Recover the interrupted reset before updating."; printf 'failed %s\n' "$(date +%s)" > "$STATE_FILE"; exit 1; }
  cd "$INSTALL_DIR"
  # Appliance updates preserve installed optional services and their configurations.
  # Provisioning or upgrading DNS/monitoring components is an explicit install task.
  if git -c "safe.directory=$INSTALL_DIR" -c core.filemode=false pull --ff-only origin main && INSTALL_ADGUARD=0 INSTALL_GATUS=0 INSTALL_BESZEL=0 bash ./install.sh; then
    printf 'Restarting NetSpecter services in readiness order...\n'
    systemctl restart netspecter-collector || true
    systemctl restart netspecter-web || true
    sleep 8
    systemctl restart netspecter-https || true
    sleep 2
    printf '=== NetSpecter UI update finished %s ===\n' "$(date)"
    printf 'finished %s\n' "$(date +%s)" > "$STATE_FILE"
  else
    rc=$?
    printf '=== NetSpecter UI update failed %s ===\n' "$(date)"
    printf 'failed %s\n' "$(date +%s)" > "$STATE_FILE"
    exit "$rc"
  fi
} >> "$LOG_FILE" 2>&1
