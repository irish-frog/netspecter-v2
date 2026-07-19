#!/bin/bash

DB="/var/lib/netspecter/netspecter.db"
SERVICE="netspecter-collector.service"
GATUS_SERVICE="gatus.service"
GATUS_URL="http://127.0.0.1:18080/api/v1/endpoints/statuses"
MAX_AGE=300
UPDATE_STATE="/var/lib/netspecter/update_state"

restart_collector() {
    logger "NetSpecter watchdog: $1"
    systemctl restart "$SERVICE"
}

collector_active() {
    systemctl is-active --quiet "$SERVICE"
}

collector_age_seconds() {
    PID=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null)
    if echo "$PID" | grep -Eq '^[0-9]+$' && [ "$PID" -gt 0 ]; then
        ps -o etimes= -p "$PID" 2>/dev/null | awk '{print $1}'
    fi
}

if [ -f "$UPDATE_STATE" ]; then
    STATE=$(awk '{print $1}' "$UPDATE_STATE" 2>/dev/null)
    STAMP=$(awk '{print $2}' "$UPDATE_STATE" 2>/dev/null)
    NOW=$(date +%s)
    if [ "$STATE" = "running" ] && echo "$STAMP" | grep -Eq '^[0-9]+$' && [ $((NOW - STAMP)) -lt 900 ]; then
        logger "NetSpecter watchdog: update in progress, skipping collector restart"
        exit 0
    fi
fi

check_gatus() {
    if ! systemctl list-unit-files "$GATUS_SERVICE" >/dev/null 2>&1; then
        return 0
    fi

    if ! systemctl is-active --quiet "$GATUS_SERVICE"; then
        logger "NetSpecter watchdog: Gatus service inactive, restarting"
        systemctl restart "$GATUS_SERVICE"
        return 0
    fi

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsS --max-time 2 "$GATUS_URL" >/dev/null 2>&1; then
            logger "NetSpecter watchdog: Gatus API unreachable, restarting"
            systemctl restart "$GATUS_SERVICE"
        fi
    fi
}

check_gatus

if [ ! -f "$DB" ]; then
    restart_collector "database missing, restarting collector"
    exit 0
fi

AGE=$(sqlite3 "$DB" "
SELECT ROUND((julianday('now','localtime') - julianday(updated_at)) * 86400, 0)
FROM collector_heartbeat
WHERE id=1;
" 2>/dev/null)

if ! echo "$AGE" | grep -Eq '^[0-9]+$'; then
    if collector_active; then
        logger "NetSpecter watchdog: collector active but heartbeat unreadable, skipping restart"
        exit 0
    fi
    restart_collector "no collector heartbeat and service inactive, restarting"
    exit 0
fi

if [ "$AGE" -gt "$MAX_AGE" ]; then
    SERVICE_AGE=$(collector_age_seconds)
    if echo "$SERVICE_AGE" | grep -Eq '^[0-9]+$' && [ "$SERVICE_AGE" -lt "$MAX_AGE" ]; then
        logger "NetSpecter watchdog: collector heartbeat stale for ${AGE}s but service only ${SERVICE_AGE}s old, waiting"
        exit 0
    fi
    restart_collector "collector stale for ${AGE}s, restarting"
fi
