#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${NETSPECTER_DATA_ROOT:-/var/lib/netspecter}"
LOG_FILE="${DATA_DIR}/daily-db-maintenance.log"
DBS=(
  "${DATA_DIR}/netspecter.db"
  "${DATA_DIR}/netspecter_dns.db"
  "${DATA_DIR}/netspecter_traffic.db"
  "${DATA_DIR}/netspecter_security.db"
)

mkdir -p "$DATA_DIR"

log() {
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"
}

vacuum_db() {
  local db="$1"
  if [ ! -s "$db" ]; then
    log "Skipping missing or empty database: $db"
    return 0
  fi

  log "Optimizing database: $db"
  if timeout 1800 sqlite3 "$db" "PRAGMA busy_timeout=5000; PRAGMA optimize; VACUUM;"; then
    log "Database maintenance complete: $db"
  else
    log "Database maintenance skipped or failed, likely busy: $db"
    return 0
  fi
}

log "NetSpecter daily database maintenance started"
for db in "${DBS[@]}"; do
  vacuum_db "$db"
done
log "NetSpecter daily database maintenance finished"
