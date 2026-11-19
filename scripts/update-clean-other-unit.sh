#!/usr/bin/env bash
# Update one existing Debian 13 x86_64 NetSpecter unit and explicitly clear collected history.
# Preview is the default. Settings/login/licence/names/rules and existing backups are retained.
set -euo pipefail
umask 077
release=fc194b15f665290c0a26455f427dc74d6eeabef8
expected="${1:-}"
mode="${2:---preview}"
[[ $# -ge 1 && $# -le 2 && ( "$mode" == --preview || "$mode" == --apply ) ]] || {
  echo "Usage: bash update-clean-netspecter.sh EXACT_HOSTNAME [--preview|--apply]" >&2; exit 2;
}
[[ $(id -u) -eq 0 ]] || { echo "Enter su - on the intended appliance first." >&2; exit 1; }
[[ -n "$expected" && $(hostname) == "$expected" ]] || { echo "Wrong hostname. Nothing changed." >&2; exit 1; }
[[ $(uname -s) == Linux && $(dpkg --print-architecture) == amd64 ]] || { echo "Requires Debian 13 x86_64." >&2; exit 1; }
. /etc/os-release
[[ "$ID" == debian && "$VERSION_ID" == 13 ]] || { echo "Requires Debian 13; no OS upgrade is performed." >&2; exit 1; }
[[ -d /opt/netspecter/.git && ! -L /opt/netspecter ]] || { echo "Existing /opt/netspecter checkout required." >&2; exit 1; }
[[ ! -e /var/lib/netspecter/history-reset.in-progress ]] || { echo "Recover the interrupted reset before updating." >&2; exit 1; }
cd /opt/netspecter
gitcmd() { git -c safe.directory=/opt/netspecter -c core.filemode=false "$@"; }
[[ $(gitcmd branch --show-current) == main ]] || { echo "Expected main branch; no checkout changed." >&2; exit 1; }
gitcmd diff --quiet HEAD -- || { echo "Local source edits need review; nothing discarded." >&2; exit 1; }
origin="$(gitcmd remote get-url origin)"
case "$origin" in
  https://github.com/irish-frog/netspecter-v2|https://github.com/irish-frog/netspecter-v2.git|git@github.com:irish-frog/netspecter-v2.git) ;;
  *) echo "Unexpected Git origin; review it before using this script." >&2; exit 1 ;;
esac
printf 'Appliance: %s\nTested release: %s\n' "$expected" "$release"
echo "Selected: update, clear ALL collected NetSpecter history, purge retired Suricata packages."
echo "Retain: settings, logins, licence, edited device names, custom rules and existing backups."
echo "Native AdGuard query logs/settings and operating-system logs are retained."
if [[ "$mode" == --preview ]]; then
  echo "PREVIEW ONLY: no source, services or collected history changed."
  echo "Apply will verify published Git ancestry, DNS continuity and reset schema before cleanup."
  echo "Run again with the exact hostname and --apply to update and clear history."
  exit 0
fi
# Serialize source installation and cleanup. The reset child inherits this same fixed lock.
[[ ! -L /run/netspecter-operation.lock ]] || { echo "Unsafe operation lock." >&2; exit 1; }
exec 9>/run/netspecter-operation.lock
python3 - <<'PY'
import os,stat
p='/run/netspecter-operation.lock';a=os.fstat(9);b=os.lstat(p)
if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_nlink!=1 or stat.S_IMODE(a.st_mode)&0o022 or (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):
 raise SystemExit('Unsafe operation lock; no update/cleanup performed')
PY
flock -n 9 || { echo "Another update or maintenance operation is running." >&2; exit 1; }
case "$(systemctl show netspecter-update.service -p ActiveState --value)" in
  inactive|failed) ;;
  *) echo "Wait for the appliance updater to finish." >&2; exit 1 ;;
esac
export GIT_TERMINAL_PROMPT=0
gitcmd fetch https://github.com/irish-frog/netspecter-v2.git main
gitcmd merge-base --is-ancestor "$release" FETCH_HEAD || { echo "Pinned release is not published on main." >&2; exit 1; }
if gitcmd merge-base --is-ancestor HEAD "$release"; then
  gitcmd merge --ff-only "$release"
elif gitcmd merge-base --is-ancestor "$release" HEAD; then
  # A later documentation-only commit is fine; never silently downgrade newer runtime code.
  while IFS= read -r path; do
    case "$path" in *.md|docs/*|scripts/update-clean-other-unit.sh) ;; *) echo "Installed runtime is newer; refresh this script instead of downgrading." >&2; exit 1 ;; esac
  done < <(gitcmd diff --name-only "$release" HEAD)
else
  echo "Source diverges from the tested release; nothing discarded." >&2; exit 1
fi
stage="$(mktemp -d /run/netspecter-update-clean.XXXXXX)"
trap 'rm -f -- "$stage/dns.json"; rmdir -- "$stage"' EXIT
python3 scripts/check-dns-continuity.py snapshot "$stage/dns.json"
INSTALL_ADGUARD=0 INSTALL_GATUS=0 INSTALL_BESZEL=0 bash install.sh
ready=0
for attempt in {1..15}; do
  if python3 scripts/verify-passive-attribution.py >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[[ "$ready" == 1 ]] || { python3 scripts/verify-passive-attribution.py; exit 1; }
python3 scripts/check-dns-continuity.py verify "$stage/dns.json"
python3 - <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'/opt/netspecter')
from services.appliance_maintenance_service import build_preview,execute_plan
from services.appliance_operation_service import operation_lock
options=dict(data_root=Path('/var/lib/netspecter'),config_path=Path('/etc/netspecter/config.json'))
plan=build_preview('all',True,**options)
rows=sum(t['rows'] for tables in plan['history']['databases'].values() for t in tables.values() if t['action']=='clear collected history')
print(json.dumps({'history_rows_selected':rows,'retired_packages':plan['packages'],'settings_preserved':True}),flush=True)
result=execute_plan(plan,**options,lock_factory=lambda:operation_lock(inherited_fd=9))
print(json.dumps({'status':'complete',**result},indent=2),flush=True)
PY
python3 scripts/check-dns-continuity.py verify "$stage/dns.json"
systemctl is-active netspecter-collector netspecter-web netspecter-https netspecter-tls-inspector netspecter-softflowd
echo "COMPLETE: software updated, collected history cleared, retired IDS packages purged."
echo "Saved settings retained. Fresh traffic starts accumulating immediately."
