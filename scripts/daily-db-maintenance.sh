#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${NETSPECTER_DATA_ROOT:-/var/lib/netspecter}"
INSTALL_DIR="${NETSPECTER_INSTALL_ROOT:-/opt/netspecter}"
PYTHON_BIN="${NETSPECTER_PYTHON:-${INSTALL_DIR}/venv/bin/python}"
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
if [ -x "$PYTHON_BIN" ] && [ -d "$INSTALL_DIR" ]; then
  log "Pruning raw Suricata logs"
  if (cd "$INSTALL_DIR" && timeout 600 "$PYTHON_BIN" -c "from netspecter_config import cfg; from live_packet_collector import prune_suricata_raw_logs; prune_suricata_raw_logs(cfg())"); then
    log "Suricata raw log prune complete"
  else
    log "Suricata raw log prune skipped or failed"
  fi

  log "Rolling up and pruning raw DNS history"
  if (cd "$INSTALL_DIR" && timeout 1800 "$PYTHON_BIN" -c "from netspecter_config import cfg; from netspecter_db import connect_db, init_db; from services.dns_rollup_service import prune_dns_history; init_db(); con=connect_db(); prune_dns_history(con, cfg()); con.commit(); con.close()"); then
    log "DNS rollup and raw prune complete"
  else
    log "DNS rollup and raw prune skipped or failed, likely busy"
  fi
else
  log "Skipping Python maintenance; Python runtime not found: $PYTHON_BIN"
fi
for db in "${DBS[@]}"; do
  vacuum_db "$db"
done
log "NetSpecter daily database maintenance finished"
