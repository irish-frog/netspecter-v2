#!/usr/bin/env bash
set -euo pipefail

SERVICE="${SERVICE:-netspecter-collector.service}"
DB_PATH="${NETSPECTER_DB_PATH:-/var/lib/netspecter/netspecter.db}"
TRAFFIC_DB_PATH="${NETSPECTER_TRAFFIC_DB_PATH:-/var/lib/netspecter/netspecter_traffic.db}"
NFT_FAMILY="${NFT_FAMILY:-bridge}"
NFT_TABLE="${NFT_TABLE:-netspecter}"
NFT_CHAIN="${NFT_CHAIN:-forward}"
LIMIT="${LIMIT:-10}"
CONNTRACK_SCAN_LIMIT="${CONNTRACK_SCAN_LIMIT:-20000}"

metric() {
  printf '%-38s %s\n' "$1" "$2"
}

sql() {
  sqlite3 -header -column "$traffic_db" "$1"
}

rule_count() {
  local pattern="$1"
  if command -v nft >/dev/null 2>&1; then
    nft list chain "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" 2>/dev/null | grep -c "$pattern" || true
  else
    printf "n/a"
  fi
}

traffic_db="$DB_PATH"
if [ -r "$TRAFFIC_DB_PATH" ] && sqlite3 "$TRAFFIC_DB_PATH" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='traffic_intervals' LIMIT 1;" 2>/dev/null | grep -q 1; then
  traffic_db="$TRAFFIC_DB_PATH"
fi

if [ ! -r "$traffic_db" ]; then
  echo "Traffic database is not readable: $traffic_db" >&2
  exit 1
fi

echo "NetSpecter destination visibility audit"
echo "Traffic DB: $traffic_db"
echo

metric "classification_nft_rules" "$(rule_count 'netspecter:classify:')"
metric "visibility_nft_rules" "$(rule_count 'netspecter:visible:')"
metric "estimated_nft_rules" "$(rule_count 'netspecter:estimated:')"
metric "classification_targets" "$(awk -v n="$(rule_count 'netspecter:classify:')" 'BEGIN { if (n ~ /^[0-9]+$/) printf "%d", n / 2; else print n }')"
metric "visibility_targets" "$(awk -v n="$(rule_count 'netspecter:visible:')" 'BEGIN { if (n ~ /^[0-9]+$/) printf "%d", n / 2; else print n }')"
metric "estimated_targets" "$(awk -v n="$(rule_count 'netspecter:estimated:')" 'BEGIN { if (n ~ /^[0-9]+$/) printf "%d", n / 2; else print n }')"
echo

echo "Recent collector target install log"
journalctl -u "$SERVICE" -n 300 --no-pager 2>/dev/null |
  grep -Ei "nftables traffic counters installed|classification target|visibility target|conntrack|Destination visibility|Recent visibility|failed|error" |
  tail -20 || true
echo

echo "Coverage by device, sorted by missing destination-visible traffic"
sql "
WITH totals AS (
  SELECT ip, SUM(total_mb) AS total_mb
  FROM traffic_intervals
  WHERE day=date('now','localtime')
  GROUP BY ip
),
visible AS (
  SELECT ip, SUM(total_mb) AS destination_visible_mb
  FROM remote_traffic_intervals
  WHERE day=date('now','localtime')
  GROUP BY ip
),
attributed AS (
  SELECT ip, SUM(total_mb) AS attributed_mb
  FROM estimated_app_traffic
  WHERE day=date('now','localtime')
  GROUP BY ip
)
SELECT
  totals.ip AS device_ip,
  ROUND(totals.total_mb, 1) AS total_mb,
  ROUND(COALESCE(visible.destination_visible_mb, 0), 1) AS destination_visible_mb,
  ROUND(totals.total_mb - COALESCE(visible.destination_visible_mb, 0), 1) AS missing_mb,
  ROUND(100.0 * COALESCE(visible.destination_visible_mb, 0) / NULLIF(totals.total_mb, 0), 1) AS visibility_percent,
  ROUND(COALESCE(attributed.attributed_mb, 0), 1) AS attributed_mb
FROM totals
LEFT JOIN visible ON visible.ip = totals.ip
LEFT JOIN attributed ON attributed.ip = totals.ip
ORDER BY missing_mb DESC
LIMIT $LIMIT;
"
echo

top_ips="$(
  sqlite3 "$traffic_db" "
  WITH totals AS (
    SELECT ip, SUM(total_mb) AS total_mb
    FROM traffic_intervals
    WHERE day=date('now','localtime')
    GROUP BY ip
  ),
  visible AS (
    SELECT ip, SUM(total_mb) AS visible_mb
    FROM remote_traffic_intervals
    WHERE day=date('now','localtime')
    GROUP BY ip
  )
  SELECT totals.ip
  FROM totals
  LEFT JOIN visible ON visible.ip=totals.ip
  ORDER BY totals.total_mb - COALESCE(visible.visible_mb,0) DESC
  LIMIT $LIMIT;
  " | tr '\n' ' '
)"

echo "Top known remote destinations for missing devices"
if [ -n "${top_ips// }" ]; then
  in_list="$(printf "%s\n" $top_ips | awk '{ printf "%s'\''%s'\''", sep, $1; sep="," }')"
  sql "
  SELECT ip AS device_ip, remote_ip, category, ROUND(SUM(total_mb), 1) AS visible_mb
  FROM remote_traffic_intervals
  WHERE day=date('now','localtime')
    AND ip IN ($in_list)
  GROUP BY ip, remote_ip, category
  ORDER BY visible_mb DESC
  LIMIT 50;
  "
else
  echo "No top devices found."
fi
echo

echo "Current nft targets for missing devices"
if command -v nft >/dev/null 2>&1 && [ -n "${top_ips// }" ]; then
  nft list chain "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" 2>/dev/null |
    grep -E "netspecter:(classify|visible|estimated):" |
    grep -Ff <(printf "%s\n" $top_ips) |
    head -80 || true
else
  echo "nft unavailable or no top devices."
fi
echo

echo "Conntrack pair sample for missing devices"
if [ -r /proc/net/nf_conntrack ]; then
  conntrack_source="cat /proc/net/nf_conntrack"
elif [ -r /proc/net/ip_conntrack ]; then
  conntrack_source="cat /proc/net/ip_conntrack"
elif command -v conntrack >/dev/null 2>&1; then
  conntrack_source="conntrack -L -f ipv4 2>/dev/null"
else
  conntrack_source=""
fi

if [ -n "$conntrack_source" ] && [ -n "${top_ips// }" ]; then
  eval "$conntrack_source" |
    head -n "$CONNTRACK_SCAN_LIMIT" |
    awk -v ips="$top_ips" '
      BEGIN {
        split(ips, iplist, " ")
        for (i in iplist) if (iplist[i] != "") wanted[iplist[i]]=1
      }
      {
        delete srcs; delete dsts; srcn=0; dstn=0
        for (i=1; i<=NF; i++) {
          if ($i ~ /^src=/) { v=$i; sub(/^src=/, "", v); srcs[++srcn]=v }
          if ($i ~ /^dst=/) { v=$i; sub(/^dst=/, "", v); dsts[++dstn]=v }
        }
        for (i=1; i<=srcn && i<=dstn; i++) {
          src=srcs[i]; dst=dsts[i]
          if (wanted[src] && dst !~ /^192\.168\.1\./) print src, dst
          else if (wanted[dst] && src !~ /^192\.168\.1\./) print dst, src
        }
      }' |
    sort | uniq -c | sort -nr | head -50 || true
else
  echo "No conntrack source available or no top devices."
fi
