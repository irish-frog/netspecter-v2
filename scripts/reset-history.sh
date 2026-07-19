#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${NETSPECTER_DATA_ROOT:-/var/lib/netspecter}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$DATA_DIR/reset-history-$STAMP"

echo "=== NetSpecter history reset ==="
echo "Keeping config in /etc/netspecter and preserving a local backup in:"
echo "  $BACKUP_DIR"

systemctl stop netspecter-web netspecter-https netspecter-collector >/dev/null 2>&1 || true

mkdir -p "$BACKUP_DIR"

for name in \
  netspecter.db \
  netspecter.db-wal \
  netspecter.db-shm \
  netspecter_dns.db \
  netspecter_dns.db-wal \
  netspecter_dns.db-shm \
  netspecter_traffic.db \
  netspecter_traffic.db-wal \
  netspecter_traffic.db-shm \
  netspecter_security.db \
  netspecter_security.db-wal \
  netspecter_security.db-shm \
  cache.json \
  live_snapshot.json
do
  if [ -e "$DATA_DIR/$name" ]; then
    mv "$DATA_DIR/$name" "$BACKUP_DIR/$name"
  fi
done

touch "$DATA_DIR/netspecter.db" \
  "$DATA_DIR/netspecter_dns.db" \
  "$DATA_DIR/netspecter_traffic.db" \
  "$DATA_DIR/netspecter_security.db"
echo "{}" > "$DATA_DIR/cache.json"
chmod 600 "$DATA_DIR"/netspecter*.db "$DATA_DIR/cache.json"

echo "History reset complete. Run:"
echo "  bash ./install.sh"
echo "  systemctl restart netspecter-web netspecter-https netspecter-collector"
