#!/usr/bin/env bash
set -euo pipefail

SERVICE="${SERVICE:-netspecter-collector.service}"
DB_PATH="${NETSPECTER_DB_PATH:-/var/lib/netspecter/netspecter.db}"
NFT_FAMILY="${NFT_FAMILY:-bridge}"
NFT_TABLE="${NFT_TABLE:-netspecter}"
NFT_CHAIN="${NFT_CHAIN:-forward}"
WINDOW_MINUTES="${WINDOW_MINUTES:-5}"
JOURNAL_LINES="${JOURNAL_LINES:-300}"

metric() {
  printf '%-42s %s\n' "$1" "$2"
}

avg_from_journal() {
  local key="$1"
  journalctl -u "$SERVICE" -n "$JOURNAL_LINES" --no-pager 2>/dev/null |
    awk -v key="$key" '
      match($0, key "=[0-9.]+s") {
        value = substr($0, RSTART + length(key) + 1, RLENGTH - length(key) - 2)
        total += value
        count += 1
      }
      END {
        if (count > 0) {
          printf "%.3fs (%d samples)", total / count, count
        } else {
          printf "n/a"
        }
      }'
}

sum_from_sql() {
  local sql="$1"
  if [ -r "$DB_PATH" ] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB_PATH" "$sql" 2>/dev/null || printf "n/a"
  else
    printf "n/a"
  fi
}

rule_count() {
  local pattern="$1"
  if command -v nft >/dev/null 2>&1; then
    nft list chain "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" 2>/dev/null | grep -c "$pattern" || true
  else
    printf "n/a"
  fi
}

main_pid="$(systemctl show "$SERVICE" -p MainPID --value 2>/dev/null || true)"
rss_kb="n/a"
if [ -n "$main_pid" ] && [ "$main_pid" != "0" ] && [ -r "/proc/$main_pid/status" ]; then
  rss_kb="$(awk '/VmRSS:/ {print $2 " kB"}' "/proc/$main_pid/status")"
fi

estimated_rows="$(sum_from_sql "SELECT COUNT(*) FROM estimated_app_traffic WHERE ts >= datetime('now', 'localtime', '-$WINDOW_MINUTES minutes');")"
destination_rows="$(sum_from_sql "SELECT COUNT(*) FROM remote_traffic_intervals WHERE ts >= datetime('now', 'localtime', '-$WINDOW_MINUTES minutes');")"

echo "NetSpecter attribution impact sample"
echo "Window: last ${WINDOW_MINUTES} minute(s)"
echo
metric "collector_loop_avg" "$(avg_from_journal total)"
metric "traffic_fact_write_avg" "$(avg_from_journal traffic_fact_write)"
metric "estimated_write_avg" "$(avg_from_journal estimated_write)"
metric "destination_write_avg" "$(avg_from_journal destination_write)"
metric "classification_nft_rules" "$(rule_count 'netspecter:classify:')"
metric "estimated_nft_rules" "$(rule_count 'netspecter:estimated:')"
metric "estimated_rows_window" "$estimated_rows"
metric "destination_rows_window" "$destination_rows"
metric "estimated_rows_per_sec" "$(awk -v rows="$estimated_rows" -v minutes="$WINDOW_MINUTES" 'BEGIN { if (rows ~ /^[0-9]+$/) printf "%.3f", rows / (minutes * 60); else print "n/a" }')"
metric "destination_rows_per_sec" "$(awk -v rows="$destination_rows" -v minutes="$WINDOW_MINUTES" 'BEGIN { if (rows ~ /^[0-9]+$/) printf "%.3f", rows / (minutes * 60); else print "n/a" }')"
metric "collector_rss" "$rss_kb"
