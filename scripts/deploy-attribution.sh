#!/usr/bin/env bash
# Explicit deployment and optional history cleanup, on the appliance running this command only.
set -euo pipefail
expected=""; apply=0; reset_history=0; purge_ids=0; networks=()
while (($#)); do
  case "$1" in
    --expected-hostname) expected="${2:?Missing hostname}"; shift 2 ;;
    --apply) apply=1; shift ;;
    --preflight) apply=0; shift ;;
    --reset-history) reset_history=1; shift ;;
    --purge-retired-ids) purge_ids=1; shift ;;
    --internal-network) networks+=(--internal-network "${2:?Missing CIDR}"); shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ $(id -u) -eq 0 ]] || { echo "Run as root (su - after SSH)." >&2; exit 1; }
[[ -n "$expected" && $(hostname) == "$expected" ]] || { echo "Supply this appliance's exact --expected-hostname. No changes made." >&2; exit 1; }
cd "$(dirname "$0")/.."
[[ $(pwd -P) == /opt/netspecter ]] || { echo "Deploy from the updated /opt/netspecter checkout." >&2; exit 1; }
[[ ! -e /var/lib/netspecter/history-reset.in-progress ]] || { echo "Recover the interrupted history reset first." >&2; exit 1; }
bash scripts/install-tls-inspector.sh --verify-only
python3 scripts/configure-passive-attribution.py "${networks[@]}" >/dev/null
if (( ! apply )); then echo "Preflight passed; no services/configuration/history changed."; exit 0; fi
dns_state="/run/netspecter-dns-check-$$.json"
trap 'rm -f -- "$dns_state"' EXIT
python3 scripts/check-dns-continuity.py snapshot "$dns_state"
INSTALL_ADGUARD=0 INSTALL_GATUS=0 INSTALL_BESZEL=0 bash install.sh
if ((${#networks[@]})); then python3 scripts/configure-passive-attribution.py --activate "${networks[@]}" >/dev/null; fi
systemctl restart netspecter-collector
systemctl restart netspecter-softflowd netspecter-tls-inspector
sleep 3
python3 scripts/verify-passive-attribution.py
if ((purge_ids)); then
  installed=()
  for package in suricata suricata-update; do
    if [[ $(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true) == installed ]]; then installed+=("$package"); fi
  done
  if ((${#installed[@]})); then
    removal_plan="$(LC_ALL=C apt-get -s purge --no-auto-remove "${installed[@]}")"
    while read -r package; do
      case "$package" in suricata|suricata-update) ;; *) echo "Refusing unexpected package removal: $package" >&2; exit 1 ;; esac
    done < <(printf '%s\n' "$removal_plan" | awk '/^(Remv|Purg) / {print $2}')
    apt-get purge -y --no-auto-remove "${installed[@]}"
  fi
fi
python3 scripts/check-dns-continuity.py verify "$dns_state"
if ((reset_history)); then
  python3 scripts/reset-collected-history.py --apply --expected-hostname "$expected"
fi
python3 scripts/verify-passive-attribution.py
python3 scripts/check-dns-continuity.py verify "$dns_state"
echo "Deployment complete. Settings, credentials and licences retained."
