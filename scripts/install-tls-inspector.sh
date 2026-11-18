#!/usr/bin/env bash
# Stage the validated sensor and private intake. Activation/restarts belong to install/deploy.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
cd "$(dirname "$0")/.."
install_dir="$(pwd -P)"
bundle="${NETSPECTER_SENSOR_BUNDLE:-$install_dir/inspector/prebuilt/linux-x86_64}"
[[ $(uname -m) == x86_64 ]] || { echo "This sensor bundle requires Linux x86_64." >&2; exit 1; }
python3 inspector/build_manifest.py verify "$bundle"
python3 - <<'PY'
import os
value=os.confstr('CS_GNU_LIBC_VERSION').split()[-1]
if tuple(map(int,value.split('.')[:2]))<(2,39):raise SystemExit('Sensor requires glibc 2.39 or newer; no files changed.')
PY
mapfile -t settings < <(python3 scripts/configure-passive-attribution.py)
[[ ${#settings[@]} -eq 2 ]] || { echo "Configuration validation failed." >&2; exit 1; }
iface="${settings[0]}"; port="${settings[1]}"
[[ -d "/sys/class/net/$iface/bridge" ]] || { echo "Configured capture interface must be an existing Linux bridge: $iface" >&2; exit 1; }
if [[ ${1:-} == --verify-only ]]; then exit 0; fi
if ! command -v softflowd >/dev/null 2>&1 || ! ldconfig -p | grep 'libpcap.so.0.8' >/dev/null; then
  apt-get update
  apt-get install -y --no-install-recommends softflowd libpcap0.8t64
fi
for group in netspecter-metadata netspecter-flow; do
  getent group "$group" >/dev/null || groupadd --system "$group"
done
for name in netspecter-tls netspecter-flow; do
  group="$name"; [[ $name == netspecter-tls ]] && group=netspecter-metadata
  if ! id "$name" >/dev/null 2>&1; then useradd --system --gid "$group" --home-dir /nonexistent --shell /usr/sbin/nologin "$name"; fi
  [[ $(id -u "$name") -ne 0 ]] || { echo "Sensor identities must not be root." >&2; exit 1; }
done
[[ ! -L "$install_dir/bin" ]] || { echo "Refusing linked binary directory." >&2; exit 1; }
install -d -o root -g root -m 755 "$install_dir/bin"
binary_stage="$(mktemp "$install_dir/bin/.tls-inspector-XXXXXX")"
trap 'rm -f -- "$binary_stage"' EXIT
install -o root -g root -m 755 "$bundle/netspecter-tls-inspector" "$binary_stage"
mv -f -- "$binary_stage" "$install_dir/bin/netspecter-tls-inspector"
"$install_dir/bin/netspecter-tls-inspector" --version
install -o root -g root -m 644 systemd/netspecter-tls-inspector.service /etc/systemd/system/
install -o root -g root -m 644 systemd/netspecter-softflowd.service /etc/systemd/system/
install -o root -g root -m 644 systemd/netspecter-tls-metadata.socket /etc/systemd/system/
install -o root -g root -m 644 systemd/netspecter-tls-metadata.conf /usr/lib/tmpfiles.d/
systemd-tmpfiles --create /usr/lib/tmpfiles.d/netspecter-tls-metadata.conf
printf 'CAPTURE_INTERFACE=%s\nNETFLOW_PORT=%s\n' "$iface" "$port" > /etc/netspecter/tls-inspector.env
chown root:root /etc/netspecter/tls-inspector.env
chmod 640 /etc/netspecter/tls-inspector.env
install -d -o root -g root -m 755 /etc/systemd/system/netspecter-collector.service.d
printf '[Unit]\nRequires=netspecter-tls-metadata.socket\nAfter=netspecter-tls-metadata.socket\n' > /etc/systemd/system/netspecter-collector.service.d/passive-attribution.conf
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/netspecter-tls-inspector.service /etc/systemd/system/netspecter-softflowd.service /etc/systemd/system/netspecter-tls-metadata.socket
python3 scripts/configure-passive-attribution.py --activate >/dev/null
systemctl disable --now suricata softflowd >/dev/null 2>&1 || true
echo "Passive attribution staged. Existing settings and secrets preserved; no history reset performed."
