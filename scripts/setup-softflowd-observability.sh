#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/netspecter}"
CONFIG_PATH="${NETSPECTER_CONFIG_PATH:-/etc/netspecter/config.json}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root." >&2
  exit 1
fi

if ! command -v softflowd >/dev/null 2>&1; then
  apt-get update
  apt-get install -y softflowd
fi

iface="$(
  python3 - "$CONFIG_PATH" <<'PY'
import json, sys
path=sys.argv[1]
try:
    data=json.load(open(path))
except Exception:
    data={}
print(data.get("packet_iface") or "br0")
PY
)"

port="$(
  python3 - "$CONFIG_PATH" <<'PY'
import json, sys
path=sys.argv[1]
try:
    data=json.load(open(path))
except Exception:
    data={}
print(int(data.get("netflow_receiver_port") or 2055))
PY
)"

active="$(
  python3 - "$CONFIG_PATH" <<'PY'
import json, sys
path=sys.argv[1]
try:
    data=json.load(open(path))
except Exception:
    data={}
print(int(data.get("softflowd_active_timeout_seconds") or 60))
PY
)"

inactive="$(
  python3 - "$CONFIG_PATH" <<'PY'
import json, sys
path=sys.argv[1]
try:
    data=json.load(open(path))
except Exception:
    data={}
print(int(data.get("softflowd_inactive_timeout_seconds") or 15))
PY
)"

cat >/etc/default/softflowd <<EOF
INTERFACE="$iface"
OPTIONS="-n 127.0.0.1:$port -v 9 -t maxlife=$active -t expint=$inactive"
EOF

systemctl enable softflowd
systemctl restart softflowd
systemctl restart netspecter-collector.service

echo "softflowd exporting NetFlow v9 from $iface to 127.0.0.1:$port"
echo "active_timeout=${active}s inactive_timeout=${inactive}s"
