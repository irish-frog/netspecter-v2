#!/usr/bin/env bash
# Bootstrap the tested Git bundle on a currently inaccessible/third appliance later.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo "Use a root shell (su - after SSH)." >&2; exit 1; }
package_dir="$(cd "$(dirname "$0")" && pwd -P)"
expected="${1:-}"
[[ -n "$expected" && $(hostname) == "$expected" ]] || { echo "Usage: bash deploy-from-bundle.sh EXACT_APPLIANCE_HOSTNAME [--preflight | --apply --reset-history --purge-retired-ids]" >&2; exit 2; }
shift
mapfile -t package < <(python3 - "$package_dir" <<'PY'
import hashlib,json,re,sys
from pathlib import Path
root=Path(sys.argv[1]);metadata=json.loads((root/'bundle.json').read_text())
path=root/'netspecter-v2.gitbundle'
if path.is_symlink() or not re.fullmatch('[0-9a-f]{40}',metadata['commit']):raise SystemExit('Unsafe deployment bundle')
if hashlib.sha256(path.read_bytes()).hexdigest()!=metadata['sha256']:raise SystemExit('Deployment bundle checksum mismatch')
print(metadata['commit']);print(str(path))
PY
)
[[ ${#package[@]} -eq 2 ]] || { echo "Package verification failed; no cleanup performed." >&2; exit 1; }
cd /opt/netspecter
gitcmd() { git -c safe.directory=/opt/netspecter -c core.filemode=false "$@"; }
[[ $(gitcmd branch --show-current) == main ]] || { echo "Expected main branch; no checkout changed." >&2; exit 1; }
gitcmd diff --quiet HEAD -- || { echo "Local source edits need review; nothing discarded." >&2; exit 1; }
gitcmd bundle verify "${package[1]}"
gitcmd fetch "${package[1]}" refs/netspecter/deployment-bundle
[[ $(gitcmd rev-parse FETCH_HEAD) == "${package[0]}" ]] || { echo "Unexpected bundle revision." >&2; exit 1; }
gitcmd merge --ff-only FETCH_HEAD
# No network Git access is required beyond this point. Debian packages may need apt access.
exec bash scripts/deploy-attribution.sh --expected-hostname "$expected" "$@"
