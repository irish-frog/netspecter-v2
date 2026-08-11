Handoff Summary
Repo:
C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Branch:
main
Remote:
https://github.com/irish-frog/netspecter-v2.git
Latest pushed commits:
f929887 Fix Suricata informational alert severity mapping
30bddbb Classify Steam IDS user-agent as informational
Current state:
GitHub is updated.
Working tree was clean after push, except Git warning that .pytest_cache/ cannot be opened due permissions.
Key IDS severity changes:
ET INFO external-IP lookup alerts are Informational.
External-IP lookup alerts are labeled External IP discovery.
.biz and .management DNS observations are Low, not High/Critical.
Truncated packet decoder alerts are Diagnostic/hidden by default.
ET USER_AGENTS Steam HTTP Client User-Agent is Informational.
Steam override stores application=Steam, category=Gaming.
ET USER_AGENTS* defaults to Informational unless a future explicit malicious override exists.
Informational/default-suppressed alerts stay searchable in expanded/raw IDS history but do not show in High/Critical totals and do not notify by default.
Suricata policy/privacy categories no longer drive Critical classification on their own.
Data/schema changes:
ids_events now has:first_seen
last_seen
alert_count
application

Duplicate alert aggregation uses signature/signature ID, source, destination/domain, protocol, and configurable time bucket.
Existing alerts are reclassified by collector import/retention and by scripts/post-update-maintenance.sh.
Files changed in the latest Steam commit:
netspecter_ids.py
netspecter_db.py
tests/test_ids_eve.py
Validation run:
python -m pytest tests/test_ids_eve.py tests/test_ids_notifications.py -q
Result:
22 passed
Compile check passed:
python -m py_compile netspecter_ids.py netspecter_db.py live_packet_collector.py app.py tests/test_ids_eve.py tests/test_ids_notifications.py
Box update command given to user:
cd /opt/netspecter
git pull
./scripts/post-update-maintenance.sh
systemctl restart netspecter-web netspecter-collector
Important note:
The changes apply to new installs because the defaults are in netspecter_ids.py and the schema is in netspecter_db.py. Existing installs get migrated/reclassified by post-update maintenance.


6:29 PM

Handoff Summary
Project: netspecter-v2
Repo: https://github.com/irish-frog/netspecter-v2
Local path: C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Box path: /opt/netspecter
Current confirmed GitHub main: c77c34b Inline allowlist proxy redirects
Main work done:
Fixed multiple CodeQL alerts around path injection, XSS, redirect handling, stack trace exposure, clear-text config handling, and HTTP response splitting.
Removed/stripped GeoIP remnants.
Cleaned Git history earlier and force-aligned main to a clean repo history.
Cleaned branches so only main remains.
Updated the speed test graph to a 7-day point/line trend design with separate latency axis and summary cards.
Removed the random “no entry” cursor/icon styling that appeared on pages.
Improved installer/update flow:Suricata rules refresh only if missing or older than 14 days.
Fresh Suricata rules skip expensive validation/restart.
Beszel install skips reinstall when already installed.
Post-update maintenance applies logrotate fix automatically.

Confirmed GitHub had c77c34b.
Important commits near the end:
7ace0a8 Skip Suricata validation for fresh rules
c77c34b Inline allowlist proxy redirects
Current unresolved/annoying issue:
CodeQL keeps reopening HTTP Response Splitting #72 in netspecter_https_proxy.py at the Location header.
Current code is safer and preserves internal redirects:redirect_location = safe_redirect_path(response.getheader("Location") or "/")
location_header = "/"
if SAFE_REDIRECT_PATH_PATTERN.fullmatch(redirect_location):
    location_header = redirect_location
self.send_header("Location", location_header)

Security-wise it only allows relative local redirect paths.
CodeQL may still see taint from upstream Location.
The CodeQL-cleanest fix would be:if 300 <= response.status < 400:
    self.send_header("Location", "/")
But that may make redirects less exact, so we did not apply it.
Better future fix may be a strict known-route allowlist rather than always /.
Box update command used/recommended:
cd /opt/netspecter
git fetch origin
git reset --hard origin/main
git rev-parse --short HEAD
bash ./install.sh
Expected HEAD after latest known push:
c77c34b
If installer pauses after Suricata message, verify it actually pulled beyond 11b3883; the real Suricata skip fix was 7ace0a8.
Useful health checks for box:
systemctl --no-pager --failed
systemctl --no-pager status netspecter-web netspecter-https netspecter-collector suricata logrotate

sqlite3 /var/lib/netspecter/netspecter.db 'PRAGMA integrity_check;'
sqlite3 /var/lib/netspecter/netspecter_dns.db 'PRAGMA integrity_check;'
sqlite3 /var/lib/netspecter/netspecter_traffic.db 'PRAGMA integrity_check;'

for path in / /devices /traffic /history /applications /blocked /ids-alerts /health /adguard /monitor /speed-tests; do
  curl -k -o /dev/null -s -w "$path %{http_code} %{time_total}s\n" https://127.0.0.1:9443$path
done
Known box result before latest pushes:
Routes returned 302 quickly, around 0.05-0.07s, because unauthenticated redirects to login are normal.
logrotate was fixed and ran successfully.
systemctl --failed showed zero failed units.
Suricata was active after earlier maintenance.
Notes for next assistant:
User prefers “if safe, do it, commit/push”.
Be cautious with the proxy redirect fix: user does not want to break redirects unless needed.
If CodeQL still complains, propose either:route allowlist for known internal paths, or
final constant / only if user accepts possible redirect precision loss.

Always confirm GitHub state with:git log -1 --oneline
git rev-parse --short origin/main
git status --short --branch

Local repo often shows:warning: could not open directory '.pytest_cache/': Permission denied
This is local noise only.
















Approve for me







5.6 TerraExtra High5.6 TerraExtra High5.5Light

Handoff Summary
Project: netspecter-v2
Repo: https://github.com/irish-frog/netspecter-v2
Local path: C:\Users\gavin\OneDrive - tech-unlimited.co.za\Documents\Website\netspecter-v2
Box path: /opt/netspecter
Current confirmed GitHub main: c77c34b Inline allowlist proxy redirects
Main work done:
Fixed multiple CodeQL alerts around path injection, XSS, redirect handling, stack trace exposure, clear-text config handling, and HTTP response splitting.
Removed/stripped GeoIP remnants.
Cleaned Git history earlier and force-aligned main to a clean repo history.
Cleaned branches so only main remains.
Updated the speed test graph to a 7-day point/line trend design with separate latency axis and summary cards.
Removed the random “no entry” cursor/icon styling that appeared on pages.
Improved installer/update flow:Suricata rules refresh only if missing or older than 14 days.
Fresh Suricata rules skip expensive validation/restart.
Beszel install skips reinstall when already installed.
Post-update maintenance applies logrotate fix automatically.

Confirmed GitHub had c77c34b.
Important commits near the end:
7ace0a8 Skip Suricata validation for fresh rules
c77c34b Inline allowlist proxy redirects
Current unresolved/annoying issue:
CodeQL keeps reopening HTTP Response Splitting #72 in netspecter_https_proxy.py at the Location header.
Current code is safer and preserves internal redirects:redirect_location = safe_redirect_path(response.getheader("Location") or "/")
location_header = "/"
if SAFE_REDIRECT_PATH_PATTERN.fullmatch(redirect_location):
    location_header = redirect_location
self.send_header("Location", location_header)

Security-wise it only allows relative local redirect paths.
CodeQL may still see taint from upstream Location.
The CodeQL-cleanest fix would be:if 300 <= response.status < 400:
    self.send_header("Location", "/")
But that may make redirects less exact, so we did not apply it.
Better future fix may be a strict known-route allowlist rather than always /.
Box update command used/recommended:
cd /opt/netspecter
git fetch origin
git reset --hard origin/main
git rev-parse --short HEAD
bash ./install.sh
Expected HEAD after latest known push:
c77c34b
If installer pauses after Suricata message, verify it actually pulled beyond 11b3883; the real Suricata skip fix was 7ace0a8.
Useful health checks for box:
systemctl --no-pager --failed
systemctl --no-pager status netspecter-web netspecter-https netspecter-collector suricata logrotate

sqlite3 /var/lib/netspecter/netspecter.db 'PRAGMA integrity_check;'
sqlite3 /var/lib/netspecter/netspecter_dns.db 'PRAGMA integrity_check;'
sqlite3 /var/lib/netspecter/netspecter_traffic.db 'PRAGMA integrity_check;'

for path in / /devices /traffic /history /applications /blocked /ids-alerts /health /adguard /monitor /speed-tests; do
  curl -k -o /dev/null -s -w "$path %{http_code} %{time_total}s\n" https://127.0.0.1:9443$path
done
Known box result before latest pushes:
Routes returned 302 quickly, around 0.05-0.07s, because unauthenticated redirects to login are normal.
logrotate was fixed and ran successfully.
systemctl --failed showed zero failed units.
Suricata was active after earlier maintenance.
Notes for next assistant:
User prefers “if safe, do it, commit/push”.
Be cautious with the proxy redirect fix: user does not want to break redirects unless needed.
If CodeQL still complains, propose either:route allowlist for known internal paths, or
final constant / only if user accepts possible redirect precision loss.

Always confirm GitHub state with:git log -1 --oneline
git rev-parse --short origin/main
git status --short --branch

Local repo often shows:warning: could not open directory '.pytest_cache/': Permission denied
This is local noise only.